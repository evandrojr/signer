# Repasse para revisão — Cache de CAs dos providers (TTL 1h)

> Documento destinado a uma IA revisora independente. Objetivo: permitir revisão crítica
> da mudança sem repetir a investigação do zero. Confie nos ponteiros de arquivo/linha,
> mas valide as afirmações marcadas com ⚠️ VERIFICAR.

## 1. Contexto e problema

Repositório: `demoiselle-signer` (Java, Maven multi-módulo), versão de trabalho `4.6.3-SNAPSHOT`.
Projeto de reprodução: `/home/j/repo/teste-eprocesso-signer` (consome o signer; usa `lcr-manager-sync` só disponível no Nexus Serpro via VPN).

Sintoma em produção: a mensagem `SerproNeoSignerProviderCA: ... Carregando cadeias de producao do SERPRO (NeoSigner).` reaparecia de forma recorrente.

Causa raiz (confirmada por leitura de fonte): `CAManager.getCertificateChain()` só possuía **cache por certificado** (`CAManagerCache`, chave = Subject DN + número de série). Em todo *miss*, o método chamava `getCAs()` de **todos** os providers (I/O de disco e rede) dentro de um método `synchronized` de singleton. Logo, cada certificado inédito — mesmo da mesma CA — recarregava todos os repositórios de CAs.

## 2. Solução implementada

Introduzido um **segundo nível de cache**: `ProviderCACache` guarda o conjunto consolidado (`allCAs`) de todos os providers habilitados num *snapshot* imutável, publicado atomicamente, com TTL (default 1h) e carga single-flight. `CAManager` passou a consumir esse cache em vez de recarregar providers por certificado.

### Arquivos de produção alterados/criados (commit `8a92bd0b` + `8333addd`)
- `core/.../ca/manager/ProviderCACache.java` (NOVO, ~292 linhas): o cache de CAs.
- `core/.../ca/manager/CAManager.java`: remove `synchronized` de `getCertificateChain()`, troca o laço de coleta por `ProviderCACache.getInstance().getCAs()`, adiciona log HIT/MISS. Remove imports `ArrayList`, `ProviderCA`, `ProviderCAFactory`.
- `core/.../ca/manager/CAManagerCache.java`: `HashMap` → `ConcurrentHashMap`; escritores deixam de ser `synchronized`; `getInstance()` passa a `synchronized`.
- `chain-icp-brasil/.../provider/impl/ICPBrasilOnLineSerproProviderCA.java`: (a) respeita `ConfigurationRepo.isOnline()==false` (usa só ZIP local); (b) logs DEBUG distinguindo consulta de hash remoto vs download do ZIP (item 5 de observabilidade). `ICPBrasilOnLineITIProviderCA` herda ambos.

### Testes criados
- `core/.../ca/manager/ProviderCACacheTest.java` (6 casos).
- `core/.../ca/manager/CountingTestProviderCA.java` + `core/src/test/resources/META-INF/services/org.demoiselle.signer.core.ca.provider.ProviderCA` (registro ServiceLoader do provider de teste).

### Documentação
- `README.md` (signer): seção "Cache de cadeias e de CAs" + variáveis de config.
- `webpages-signer` branch `develop`, commit `f79233d9`: seção 4.6 em `v3/v3/signer/docs/core-configuracoes-ambiente.html` + TOC em `index.html`/`core-master.html`.
- Spec: `.kiro/specs/cache-cas-providers/{requirements,design,tasks}.md`.

## 3. Design — pontos que o revisor deve checar criticamente

### 3.1 Concorrência (área de maior risco)
- `getCertificateChain()` deixou de ser `synchronized`. A serialização agora é:
  - carga de CAs: `ReentrantLock loadLock` dedicado em `ProviderCACache` (single-flight + double-check).
  - escrita no cache de cadeia: `ConcurrentHashMap` em `CAManagerCache`.
- Publicação do snapshot: `AtomicReference.set()` com `Collections.unmodifiableList(new ArrayList<>(...))`.
- ⚠️ VERIFICAR: a remoção do `synchronized` do `CAManager` depende criticamente de `CAManagerCache` ter virado `ConcurrentHashMap`. Se um revisor encontrar qualquer leitura de `HashMap` concorrente a escrita, é bug. Conferir `CAManagerCache.java` inteiro.
- ⚠️ VERIFICAR: `CAManager.isCAofCertificate()` também lê/escreve `CAManagerCache` (fora de `getCertificateChain`). Confirmar que continua seguro sem o lock do método.

### 3.2 Invalidação do cache de cadeia
- A cada (re)publicação do snapshot de CAs, `ProviderCACache` chama `CAManagerCache.getInstance().invalidate()` — inclusive em refresh por TTL de mesmo escopo. Racional: não reaproveitar cadeias construídas sobre CAs que podem ter mudado.
- ⚠️ DISCUTIR: isso significa que a cada 1h o cache de cadeia por certificado é esvaziado. Trade-off aceito (miss de construção, não de rede). Revisor pode questionar se o custo é aceitável no volume de produção.

### 3.3 Política de falha (`collectFromProviders` / `LoadResult.usable`)
- `usable == !allCAs.isEmpty()`. Falha sem snapshot anterior → `CAManagerException`. Falha com snapshot anterior → mantém o anterior + warning.
- ⚠️ VERIFICAR / FRAGILIDADE CONHECIDA: `SerproNeoSignerProviderCA.getCAs()` tem `finally { return result; }` que engole `Throwable` e pode retornar lista **parcial** sem lançar exceção. Nesse caso `usable` seria `true` e um conjunto incompleto seria publicado. O `LoadResult` só detecta falha quando o provider **lança** ou o conjunto fica **vazio**. Avaliar se isso é risco real no ambiente alvo.

### 3.4 Escopo do snapshot (`currentScopeKey`)
- Chave = `"env=" + DisablingUtil.getEnvironment() + ";providers=" + <nomes de classe ordenados>`.
- Objetivo: não misturar produção/homologação; mudança de `SIGNER_ENV` ou de providers habilitados força recarga.
- ⚠️ VERIFICAR: `DisablingUtil.getEnvironment()` retorna o valor cru de `SIGNER_ENV` (ou `""`). Confirmar que isso é suficiente — por exemplo, se dois perfis diferentes puderem produzir o mesmo conjunto de providers mas CAs distintas (não deve ocorrer, mas vale o olhar).

### 3.5 TTL e segurança
- Default 1h (`DEFAULT_TTL_MILLIS = 3_600_000L`), configurável via `SIGNER_CAMANAGER_CA_TTL_MILLIS` / `signer.camanager.ca.ttl.millis`. `0`/negativo desliga expiração por tempo.
- Janela de confiança: uma CA removida pode permanecer confiável por até 1h (ou até `invalidate()`). Documentado. Não afeta revogação (CRL/OCSP).
- ⚠️ DISCUTIR: o revisor deve julgar se 1h é um default adequado para o modelo de ameaça do ICP-Brasil (remoção de AC raiz é evento raro e lento).

## 4. Compatibilidade Java 8 (requisito do projeto)
- Projeto pinado em `source/target=1.8` (pom raiz, linhas ~114-116).
- Verificado compilando com `-Dmaven.compiler.release=8` (modo estrito que rejeita APIs > 8): BUILD SUCCESS.
- `ProviderCACache` usa só APIs Java 8 (`AtomicReference`, `ReentrantLock`, `Collections.unmodifiableList`, diamond, literal com underscore). `CaSnapshot` é classe estática (não `record`).
- Corrigido um `List.of(...)` (Java 9+) que havia no teste → `Arrays.asList(...)`.
- ⚠️ VERIFICAR: rodar `mvn -pl core,chain-icp-brasil -am test -Dmaven.compiler.release=8 -Dmaven.javadoc.skip=true`. (O javadoc plugin falha no JDK 25 local por `sun.security.*` — problema pré-existente, sem relação com esta mudança; em JDK 8 não ocorre.)

## 5. Evidências de verificação
- `core`: 52/52 testes. `chain-icp-brasil`: 9/9.
- `ProviderCACacheTest` cobre: (a) 2 certs distintos mesma CA → 1 carga; (b) 50 consultas alternadas → 1 carga; (c) 8 threads cold start → 1 carga (single-flight); (d) `invalidate()` recarrega; (e) falha total sem snapshot → `CAManagerException`; (f) falha após snapshot válido → mantém anterior.
- Cenário real do eprocesso (`FluxoEprocessoTest`, 100x alternando dois assinantes reais da MESMA CA `AC SERPRORFBv5`, via VPN/Nexus):
  - `4.6.2` (sem correção): mensagem do NeoSigner **2x**.
  - `4.6.3-SNAPSHOT` (com correção): mensagem **1x**. Teste passou (`Tests run: 1, Failures: 0`).
- ⚠️ RESSALVA: a contagem "1 carga por provider" sob concorrência foi validada em teste unitário com provider contador; em produção com providers reais confia-se no mesmo caminho de código.

## 6. O que NÃO foi alterado (preservação)
- Algoritmo de construção da cadeia (match de principals, fallback CN, `isCAofCertificate`, loop guard, `CAManagerException` quando não fecha na raiz).
- Interface `ProviderCA`, URLs/artefatos dos providers.
- Validações de confiança/validade/revogação; repositório de LCR.
- Semântica de `CAManagerConfiguration.isCached()==false` (sem cache algum).

## 7. Perguntas abertas para o revisor
1. A fragilidade 3.3 (provider que engole exceção e retorna conjunto parcial) justifica mudar o contrato de erro do `SerproNeoSignerProviderCA`?
2. A invalidação total do cache de cadeia a cada refresh de TTL (3.2) é aceitável, ou deveria ser mais granular (invalidar só cadeias afetadas por CAs removidas)?
3. O default de TTL 1h é adequado? Faz sentido TTL separado para providers embarcados (JAR) vs online?
4. Há caminhos concorrentes de `CAManagerCache` fora de `getCertificateChain` que ainda precisem de atenção após remover o `synchronized`?

## 8. Como navegar o código
- Lógica central: `core/src/main/java/org/demoiselle/signer/core/ca/manager/ProviderCACache.java` (métodos `getCAs`, `loadAndPublish`, `collectFromProviders`, `isValid`, `currentScopeKey`).
- Ponto de integração: `CAManager.getCertificateChain()` (linha ~221 em diante).
- Modo offline + logs: `ICPBrasilOnLineSerproProviderCA.getCAs()`.
- Spec e racional: `.kiro/specs/cache-cas-providers/design.md`.

## 9. Resultado da revisão independente (2026-10-30)

Revisão feita por leitura do código nos commits `8a92bd0b` + `8333addd`, com
execução de `ProviderCACacheTest` (6/6 passando). Veredito: a análise do repasse
está correta no diagnóstico e na maior parte do desenho, mas existem divergências
entre afirmações do documento e o código efetivo.

### 9.1 Bloqueantes

**B1 — `scopeKey` não reflete cadeias habilitadas/desabilitadas (contraria Req 1.4/2.5).**
`ProviderCACache.currentScopeKey()` (`ProviderCACache.java:267-274`) inclui *todos*
os providers devolvidos por `ProviderCAFactory.factory()`, que não filtra por
`DisablingUtil` (`ProviderCAFactory.java:60-72`). Como `DisablingUtil.getEnvironment()`
lê apenas `SIGNER_ENV`, mudar `SIGNER_ENABLE_CHAIN_*` (override por cadeia) **não
altera o scope**; o snapshot anterior é reusado por até o TTL. O design
(`design.md:155-156`) pressupõe `isProviderDisabled`, método que não existe. O
item 3.4 do repasse é, portanto, um gap real e não hipotético.

**B2 — Falha parcial de provider é publicada e cacheada por 1h.**
`collectFromProviders()` usa `usable = !allCAs.isEmpty()`
(`ProviderCACache.java:222`), ignorando `anyProviderFailed`. Se o provider A lança
e o B retorna CAs, o conjunto incompleto é publicado. Cadeias que dependem de A
falham por até o TTL mesmo após A se recuperar — regressão frente ao comportamento
anterior, que re-tentava todos os providers a cada lookup. Contraria o próprio
design (`design.md:144-145`, "sem erro detectável") e é mais grave que o caso 3.3.
Correção sugerida: se `anyProviderFailed`, não publicar (manter snapshot anterior)
ou usar TTL curto de retry.

**B3 — `isCached()==false` deixou de significar "sem cache algum" (seção 6 incorreta).**
`CAManager.getCertificateChain()` chama `ProviderCACache.getInstance().getCAs()`
incondicionalmente (`CAManager.java:248`), fora do bloco `if (config.isCached())`.
Antes (`8a92bd0b^`), `isCached()==false` recarregava os providers a cada chamada.
Agora há cache de CAs sempre. Ou condicionar o `ProviderCACache` a `isCached()`,
ou corrigir Req 1.5 / task 3.4 e a seção 6 deste repasse.

### 9.2 Importantes

**I1 — Corrida de re-inserção de cadeia obsoleta.**
T1 lê `allCAs` (snapshot antigo) e constrói a cadeia; T2 publica novo snapshot e
chama `invalidate()` (`ProviderCACache.java:174`); T1 então grava a cadeia velha
em `CAManagerCache.addCertificate` (`CAManager.java:305`) *após* o clear. A cadeia
construída sobre CA removida sobrevive até o próximo refresh. Mitigar com
epoch/versão verificada antes do `addCertificate`.

**I2 — `currentScopeKey()` no caminho quente.**
Executa `ServiceLoader.load` e instancia todos os providers a cada `getCAs()`,
inclusive em cache hit (`ProviderCACache.java:269-270`); `collectFromProviders`
carrega de novo (`:203`). Sem impacto de correção, mas é alocação/instanciação
desnecessária e pode disparar construtores com efeito colateral.

### 9.3 Menores

**M1 — Drift design vs código.** `design.md` usa `List.copyOf` (`:106`), `record`
(`:139`), `isProviderDisabled`/`currentEnvLabel` (`:156,159`) e invalida só em
`scopeChanged || current==null` (`:109`). A implementação real é Java 8
(`unmodifiableList`, classe estática, `getEnvironment`) e invalida em **todo**
publish (`ProviderCACache.java:174`, como descrito em 3.2). Alinhar o design.

**M2 — `tasks.md` com todos os checkboxes `[ ]`** apesar de concluído.

**M3 — Sem teste para `isOnline()==false`.** Req 2.5 e `design.md:266` preveem
teste com mock de `Downloads`; não existe. Faltam também testes para B1, B2 e B3.

### 9.4 Itens do repasse confirmados

- §3.1: `CAManagerCache` está 100% `ConcurrentHashMap`; o get/put não atômico de
  `isCAofCertificate` é inofensivo (idempotente). Seguro sem o `synchronized`.
- §3.3: confirmado `finally { return result; }` em `SerproNeoSignerProviderCA.java:108-112`.
- §4: código é compatível com Java 8 (o **design**, não).
- §5: `ProviderCACacheTest` executado nesta revisão: 6/6, sem falhas.

### 9.5 Respostas às perguntas abertas (seção 7)

1. Sim, mas priorizar B2 (falha parcial explícita) antes do swallow do Serpro (§3.3).
2. A invalidação total é aceitável; o problema é a corrida I1.
3. 1h é adequado para remoção de AC raiz, **não** para recuperação de falha parcial
   (B2). TTL separado embarcado vs online faz sentido.
4. Sim: a escrita pós-`invalidate` (I1).


## 10. Correções aplicadas após a revisão (2026-10-30)

Todos os bloqueantes e importantes endereçados; menores resolvidos. Testes: core 55/55, chain-icp-brasil 10/10 (Java 8 estrito, `-Dmaven.compiler.release=8`).

### Bloqueantes
- **B1 (scope)**: `ProviderCACache.currentScopeKey()` agora inclui o estado `isChainDisabled(<cadeia>)` de cada cadeia conhecida (`KNOWN_CHAINS`), além de `getEnvironment()`. Overrides `SIGNER_ENABLE_CHAIN_*` passam a mudar o escopo e forçar recarga. Removida a dependência do inexistente `isProviderDisabled`.
- **B2 (falha parcial)**: `collectFromProviders()` usa `usable = !allCAs.isEmpty() && !anyProviderFailed`. Se qualquer provider lança, o snapshot não é publicado — mantém o anterior (ou lança `CAManagerException` se não houver anterior). Evita cachear conjunto incompleto por 1h.
- **B3 (`isCached()==false`)**: `CAManager.getCertificateChain()` só usa `ProviderCACache` quando `isCached()`; caso contrário coleta via novo `collectCAsDirectly()` a cada chamada e não grava no cache de cadeia. Semântica histórica "sem cache algum" restaurada.

### Importantes
- **I1 (cadeia obsoleta)**: `ProviderCACache` mantém um `epoch` (AtomicLong) incrementado em cada publish e em cada `invalidate()`. `getCASet()` devolve CAs + epoch; `CAManager` só grava a cadeia se `getEpoch()` não mudou desde a leitura. Escrita obsoleta após refresh concorrente é descartada.
- **I2 (ServiceLoader no caminho quente)**: providers resolvidos uma única vez via `getProviders()` (memoizado, double-checked). `ServiceLoader` não roda mais a cada `getCAs()`/cache hit. Método `resetProvidersForTest()` para a suíte.

### Menores
- **M1**: nota de alinhamento no topo do `design.md` listando as divergências do pseudocódigo (Java 8, B1/B2/B3, epoch, memoização).
- **M2**: `tasks.md` com todos os itens marcados `[x]`.
- **M3**: adicionado `ICPBrasilOnLineSerproProviderCATest.offline_naoVaiAhRede` (confirma que `isOnline()==false` não paga latência de rede). Novos testes em `ProviderCACacheTest`: `notCached_collectsProvidersEveryCall_andDoesNotStoreChain` (B3), `epoch_changesOnPublishAndInvalidate` e `staleChainNotCached_whenEpochChanged` (I1).

### Limitação conhecida (registrada)
- O cenário B2 "parcial com 2+ providers" é validado pela lógica (`!anyProviderFailed`) e pelo caso de falha de provider único; não há teste com dois providers reais distintos registrados simultaneamente no ServiceLoader da suíte.
