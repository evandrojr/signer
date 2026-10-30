# Repasse para revisão — Cache de CAs dos providers (TTL 1h)

> Documento destinado a uma IA revisora independente. Objetivo: permitir revisão crítica
> da mudança sem repetir a investigação do zero. Confie nos ponteiros de arquivo/linha,
> mas valide as afirmações marcadas com ⚠️ VERIFICAR.
>
> **Estado atual (2026-10-30, pós 2ª rodada).** A 1ª revisão (seção 9) apontou B1–B3 e
> I1–I2; todos foram corrigidos (seção 10) e commitados. Este documento descreve o
> **código já corrigido** como base para a próxima revisão. Commits relevantes no repo
> `signer`, branch `4.6.3-SNAPSHOT`:
> - `8a92bd0b` — feat inicial (cache de CAs, TTL, concorrência).
> - `8333addd` — docs + logs hash-vs-download (item 5 de observabilidade).
> - `60e06078` — correções da revisão (B1–B3, I1–I2, M1–M3).
>
> Para revisar o HEAD atual, leia os arquivos no estado de `60e06078`. As seções 3–6
> abaixo já refletem esse estado; as seções 9–11 preservam o histórico da revisão.

## 1. Contexto e problema

Repositório: `demoiselle-signer` (Java, Maven multi-módulo), versão de trabalho `4.6.3-SNAPSHOT`.
Projeto de reprodução: `/home/j/repo/teste-eprocesso-signer` (consome o signer; usa `lcr-manager-sync` só disponível no Nexus Serpro via VPN).

Sintoma em produção: a mensagem `SerproNeoSignerProviderCA: ... Carregando cadeias de producao do SERPRO (NeoSigner).` reaparecia de forma recorrente.

Causa raiz (confirmada por leitura de fonte): `CAManager.getCertificateChain()` só possuía **cache por certificado** (`CAManagerCache`, chave = Subject DN + número de série). Em todo *miss*, o método chamava `getCAs()` de **todos** os providers (I/O de disco e rede) dentro de um método `synchronized` de singleton. Logo, cada certificado inédito — mesmo da mesma CA — recarregava todos os repositórios de CAs.

## 2. Solução implementada (estado atual)

Introduzido um **segundo nível de cache**: `ProviderCACache` guarda o conjunto consolidado (`allCAs`) de todos os providers habilitados num *snapshot* imutável, publicado atomicamente, com TTL (default 1h), carga single-flight e **epoch** de versionamento. `CAManager` consome esse cache via `getCASet()` (CAs + epoch) quando `isCached()==true`, e coleta os providers diretamente quando o cache está desligado.

### Arquivos de produção (HEAD = `60e06078`)
- `core/.../ca/manager/ProviderCACache.java` (NOVO): o cache de CAs. API pública relevante: `getCAs()`, `getCASet()` (→ `CaSet{cas, epoch}`), `getEpoch()`, `invalidate()`, `getTtlMillis()`/`setTtlMillis()`. Internos: `loadAndPublish`, `collectFromProviders` (com `LoadResult`), `currentScopeKey`, `getProviders` (memoizado), `isValid`, `resolveTtlFromConfig`, constante `KNOWN_CHAINS`.
- `core/.../ca/manager/CAManager.java`: `getCertificateChain()` **sem** `synchronized`; usa `ProviderCACache.getCASet()` quando `isCached()`, senão `collectCAsDirectly()`; grava a cadeia só se o epoch não mudou; log HIT/MISS.
- `core/.../ca/manager/CAManagerCache.java`: `HashMap` → `ConcurrentHashMap`; escritores sem `synchronized`; `getInstance()` `synchronized`.
- `chain-icp-brasil/.../provider/impl/ICPBrasilOnLineSerproProviderCA.java`: (a) respeita `ConfigurationRepo.isOnline()==false` (usa só ZIP local); (b) logs DEBUG distinguindo consulta de hash remoto vs download do ZIP. `ICPBrasilOnLineITIProviderCA` herda ambos.

### Testes
- `core/.../ca/manager/ProviderCACacheTest.java` (9 casos): distintos mesma CA→1 carga; 50 alternadas→1 carga; 8 threads→1 carga; `invalidate` recarrega; falha total→exceção; falha pós-snapshot→mantém anterior; `isCached(false)`→coleta sempre e não cacheia (B3); epoch muda em publish/invalidate (I1); cadeia não cacheada quando epoch mudou (I1).
- `core/.../ca/manager/CountingTestProviderCA.java` + `META-INF/services/...ProviderCA` (registro ServiceLoader do provider de teste).
- `chain-icp-brasil/.../ICPBrasilOnLineSerproProviderCATest.offline_naoVaiAhRede` (M3).

### Documentação
- `README.md` (signer): seção "Cache de cadeias e de CAs" + variáveis de config.
- `webpages-signer` branch `develop`, commit `f79233d9`: seção 4.6 em `v3/v3/signer/docs/core-configuracoes-ambiente.html` + TOC em `index.html`/`core-master.html`.
- Spec: `.kiro/specs/cache-cas-providers/{requirements,design,tasks}.md` (design com nota de alinhamento no topo).

## 3. Design — pontos que o revisor deve checar criticamente

### 3.1 Concorrência (área de maior risco)
- `getCertificateChain()` deixou de ser `synchronized`. A serialização agora é:
  - carga de CAs: `ReentrantLock loadLock` dedicado em `ProviderCACache` (single-flight + double-check).
  - escrita no cache de cadeia: `ConcurrentHashMap` em `CAManagerCache`.
- Publicação do snapshot: `AtomicReference.set()` com `Collections.unmodifiableList(new ArrayList<>(...))`.
- **Epoch (I1)**: `AtomicLong` incrementado em cada publish e em cada `invalidate()`. `getCASet()` devolve `CaSet{cas, epoch}`; `CAManager` só grava a cadeia se `ProviderCACache.getEpoch() == caEpoch` lido no início. Evita reintroduzir cadeia obsoleta após refresh concorrente.
- **Providers memoizados (I2)**: `getProviders()` roda `ServiceLoader` uma vez (double-checked), não a cada `getCAs()`.
- ✅ CONFIRMADO na 1ª revisão (9.4): `CAManagerCache` é 100% `ConcurrentHashMap`; o get/put não atômico de `isCAofCertificate` é idempotente e inofensivo. Seguro sem o `synchronized`.
- ⚠️ VERIFICAR: a janela do epoch (I1) reduz, mas não elimina teoricamente, toda corrida — a leitura `getEpoch()` e o `addCertificate` não são atômicos entre si. Avaliar se o residual é aceitável (o pior caso é não cachear uma cadeia válida, nunca cachear uma inválida).

### 3.2 Invalidação do cache de cadeia
- A cada (re)publicação do snapshot de CAs, `ProviderCACache` chama `CAManagerCache.getInstance().invalidate()` — inclusive em refresh por TTL de mesmo escopo. Racional: não reaproveitar cadeias construídas sobre CAs que podem ter mudado.
- ⚠️ DISCUTIR: isso significa que a cada 1h o cache de cadeia por certificado é esvaziado. Trade-off aceito (miss de construção, não de rede). Revisor pode questionar se o custo é aceitável no volume de produção.

### 3.3 Política de falha (`collectFromProviders` / `LoadResult.usable`) — CORRIGIDO (B2)
- `usable == !allCAs.isEmpty() && !anyProviderFailed`. Se **qualquer** provider lança, o conjunto não é publicado: mantém o snapshot anterior (ou lança `CAManagerException` se não houver anterior).
- ⚠️ FRAGILIDADE RESIDUAL CONHECIDA: `SerproNeoSignerProviderCA.getCAs()` tem `finally { return result; }` que engole `Throwable` e pode retornar lista **parcial sem lançar**. Nesse caminho `anyProviderFailed` fica `false` e o conjunto parcial seria publicado. A correção B2 só cobre providers que **lançam**. Resolver de fato exige mudar o contrato de erro do `SerproNeoSignerProviderCA` (resposta 1 da seção 9.5 priorizou B2 antes desse swallow). Avaliar se vale corrigir o provider.

### 3.4 Escopo do snapshot (`currentScopeKey`) — CORRIGIDO (B1)
- Chave = `"env=" + DisablingUtil.getEnvironment() + ";chains=[" + <estado isChainDisabled de cada KNOWN_CHAINS> + "]" + ";providers=" + <nomes de classe ordenados>`.
- Agora reflete overrides `SIGNER_ENABLE_CHAIN_*` (via `isChainDisabled`), não só `SIGNER_ENV`.
- ⚠️ VERIFICAR: `KNOWN_CHAINS` é uma lista fixa em `ProviderCACache` (`icp-brasil`, `icp-brasil-homolog`, `iti-homolog`, `serpro-neosigner`, `serpro-neosigner-prod`, `serpro-neosigner-homolog`). Se uma nova cadeia/módulo for adicionado ao projeto e usar `DisablingUtil`, precisa ser incluído aqui — senão seu override não muda o escopo. Confirmar se a lista cobre todas as cadeias atuais.

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

## 5. Evidências de verificação (estado atual)
- `core`: **55/55** testes. `chain-icp-brasil`: **10/10**. Java 8 estrito (`-Dmaven.compiler.release=8 -Dmaven.javadoc.skip=true`).
- `ProviderCACacheTest` (9 casos): (a) 2 certs distintos mesma CA → 1 carga; (b) 50 consultas alternadas → 1 carga; (c) 8 threads cold start → 1 carga (single-flight); (d) `invalidate()` recarrega; (e) falha total sem snapshot → `CAManagerException`; (f) falha após snapshot válido → mantém anterior; (g) `isCached(false)` → coleta a cada chamada e não cacheia (B3); (h) epoch muda em publish/invalidate (I1); (i) cadeia não sobrevive a mudança de epoch (I1).
- `ICPBrasilOnLineSerproProviderCATest.offline_naoVaiAhRede`: `isOnline()==false` retorna coleção não-nula sem incorrer na latência de rede (M3).
- Cenário real do eprocesso (`FluxoEprocessoTest`, 100x alternando dois assinantes reais da MESMA CA `AC SERPRORFBv5`, via VPN/Nexus):
  - `4.6.2` (sem correção): mensagem do NeoSigner **2x**.
  - `4.6.3-SNAPSHOT` (HEAD corrigido): mensagem **1x**. Teste passou (`Tests run: 1, Failures: 0`). Revalidado após as correções B1–B3/I1–I2.
- ⚠️ RESSALVA: a contagem "1 carga por provider" sob concorrência foi validada em teste unitário com provider contador; em produção com providers reais confia-se no mesmo caminho de código.

## 6. O que NÃO foi alterado (preservação)
- Algoritmo de construção da cadeia (match de principals, fallback CN, `isCAofCertificate`, loop guard, `CAManagerException` quando não fecha na raiz).
- Interface `ProviderCA`, URLs/artefatos dos providers.
- Validações de confiança/validade/revogação; repositório de LCR.
- Semântica de `CAManagerConfiguration.isCached()==false`: **restaurada** (B3). Sem cache, os providers são consultados a cada chamada via `CAManager.collectCAsDirectly()` e a cadeia não é gravada.

## 7. Perguntas da 1ª rodada — status
1. Provider que engole exceção e retorna conjunto parcial (3.3): **em aberto** — B2 cobriu só providers que lançam; corrigir o swallow do `SerproNeoSignerProviderCA` ainda é uma decisão pendente (ver 11.1).
2. Invalidação total do cache de cadeia a cada refresh de TTL (3.2): **aceita** pela revisão; o problema de corrida era I1, já corrigido via epoch.
3. Default de TTL 1h / TTL separado embarcado vs online: **em aberto** — 1h adequado para remoção de AC raiz; TTL separado faz sentido mas não implementado (ver 11.2).
4. Caminhos concorrentes de `CAManagerCache` fora de `getCertificateChain` (I1): corrigido via epoch; `isCAofCertificate` confirmado seguro (9.4).

## 8. Como navegar o código (HEAD `60e06078`)
- Lógica central: `core/src/main/java/org/demoiselle/signer/core/ca/manager/ProviderCACache.java` — `getCASet`/`getCAs`, `loadAndPublish`, `collectFromProviders` (`LoadResult`), `isValid`, `currentScopeKey` (+ `KNOWN_CHAINS`), `getProviders` (memoização I2), `getEpoch`/`invalidate` (epoch I1).
- Ponto de integração: `CAManager.getCertificateChain()` — ramo `isCached()` usa `getCASet()` e grava só se epoch inalterado; ramo `!isCached()` usa `collectCAsDirectly()`.
- Modo offline + logs hash-vs-download: `ICPBrasilOnLineSerproProviderCA.getCAs()`.
- Spec e racional: `.kiro/specs/cache-cas-providers/design.md` (ler a nota de alinhamento no topo).
- Histórico da 1ª revisão e correções: seções 9 e 10 deste arquivo.

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


## 11. Agenda para a 2ª rodada de revisão

O HEAD a revisar é `60e06078`. Focar nestes pontos (os demais já foram confirmados):

### 11.1 Itens ainda em aberto (decisão pendente)
- **Swallow do `SerproNeoSignerProviderCA` (resposta 3.3).** O `finally { return result; }` permite conjunto parcial sem lançar, driblando a proteção B2. Decidir: (a) mudar o provider para propagar falha de carga, ou (b) aceitar o risco documentando. Impacto: um provider embarcado parcial seria cacheado por 1h.
- **TTL separado embarcado vs online (resposta 3/9.5).** Hoje há um único TTL para o snapshot consolidado. Avaliar se vale TTL distinto (embarcado = vida do classloader; online = 1h).

### 11.2 Novos pontos introduzidos pelas correções (revisar)
- **`KNOWN_CHAINS` hardcoded (B1).** Lista fixa em `ProviderCACache`. Revisar se cobre todas as cadeias e se há risco de esquecer de atualizá-la ao adicionar um módulo. Alternativa a considerar: derivar do próprio provider (ex.: cada `ProviderCA` expor seu chain name).
- **Residual do epoch (I1).** `getEpoch()` + `addCertificate` não são atômicos entre si. Confirmar que o pior caso é apenas "deixar de cachear uma cadeia válida" (benigno), nunca cachear inválida.
- **`collectCAsDirectly()` duplica a coleta (B3).** `CAManager.collectCAsDirectly()` e `ProviderCACache.collectFromProviders()` têm laços parecidos. Avaliar duplicação vs. simplicidade; `collectCAsDirectly` não memoiza providers (intencional, pois `isCached()==false` quer recarga sempre).
- **Memoização de providers (I2) vs. testes.** `getProviders()` fixa o resultado do `ServiceLoader` no 1º uso; `resetProvidersForTest()` existe só para a suíte. Confirmar que nenhum consumidor de produção depende de reavaliar providers em runtime (env vars já são lidas no load, então não deveria).

### 11.3 Cobertura de teste a questionar
- Falta teste com **dois providers reais distintos** simultâneos para o caso parcial de B2 (ver limitação em 10). Avaliar se é necessário adicionar um segundo provider de teste no ServiceLoader.
- Não há teste de **mudança de escopo** (B1) forçando recarga ao alternar `SIGNER_ENABLE_CHAIN_*` — difícil porque env vars não mudam em runtime; avaliar teste que manipule o `scopeKey` por outro meio.

### 11.4 Como validar
```
# testes (Java 8 estrito; pular javadoc por causa do JDK 25 local)
mvn -pl core,chain-icp-brasil -am test -Dmaven.compiler.release=8 -Dmaven.javadoc.skip=true

# cenário real (requer VPN/Nexus Serpro): apontar teste-eprocesso-signer para 4.6.3-SNAPSHOT
#   e rodar FluxoEprocessoTest; esperado: NeoSigner 1x.
```
