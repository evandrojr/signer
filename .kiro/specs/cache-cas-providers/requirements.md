# Cache de CAs dos Providers - Requirements

## Introdução

Em produção a mensagem `SerproNeoSignerProviderCA: ... Carregando cadeias de producao do SERPRO (NeoSigner).` reaparece de forma recorrente. A análise das fontes em `core/.../ca/manager/CAManager.java` e dos providers em `chain-icp-brasil` e `chain-serpro-neosigner` confirmou que existe apenas **cache por certificado** (`CAManagerCache`), e não **cache do conjunto de CAs fornecidas pelos providers**.

Consequência: a primeira validação de qualquer certificado ainda não conhecido dispara `provider.getCAs()` em **todos** os providers, mesmo que o certificado pertença a uma cadeia já atendida pelas CAs disponíveis. Com vários assinantes, isso recarrega repetidamente todos os repositórios de CAs — incluindo I/O de rede e leitura/parse de ZIP — dentro de um bloco `synchronized` de um singleton.

Esta spec define o comportamento esperado de um cache de CAs separado do cache de cadeia, com política de atualização explícita, concorrência correta, tratamento de falha e observabilidade. A spec **não** altera validações de confiança, validade ou revogação, nem mantém dados de revogação (LCR) em cache.

## Glossário

- **CA**: Autoridade Certificadora (`X509Certificate` de uma AC raiz ou intermediária).
- **Conjunto de CAs (`allCAs`)**: União das CAs retornadas por `getCAs()` de todos os providers habilitados.
- **Cache de cadeia**: Cache existente em `CAManagerCache` que mapeia `SubjectDN + serialNumber` de um certificado final para sua cadeia construída.
- **Cache de CAs**: Novo cache que guarda o conjunto `allCAs` consolidado, reutilizável entre certificados distintos.
- **Provider embarcado**: Provider cujas CAs vêm do classpath/JAR (`SerproNeoSignerProviderCA`, `ICPBrasilProviderCA`).
- **Provider online**: Provider que consulta/baixa artefatos remotos (`ICPBrasilOnLineSerproProviderCA`, `ICPBrasilOnLineITIProviderCA`) ou lê ZIP do user home (`ICPBrasilUserHomeProviderCA`).
- **Escopo do cache de CAs**: Combinação de ambiente (prod/hom/both via `DisablingUtil`) e conjunto de providers habilitados que define a validade do conjunto cacheado.
- **Publicação atômica**: Troca da referência do conjunto de CAs de forma que leitores vejam sempre um conjunto consistente, sem estado intermediário.
- **Single-flight**: Garantia de que apenas uma carga/atualização do conjunto de CAs ocorre por vez, evitando downloads duplicados.

## Requisitos

### Requisito 1 — Separar cache de CAs do cache de cadeia

**User Story:** Como operador da aplicação em produção, quero que o conjunto de CAs seja reaproveitado entre certificados distintos, para que um novo assinante não force a recarga de todos os repositórios de CAs.

#### Acceptance Criteria

1. QUANDO `CAManager.getCertificateChain()` é chamado para um certificado ausente do cache de cadeia E o conjunto de CAs já está carregado e válido, ENTÃO o sistema NÃO DEVE chamar `getCAs()` de nenhum provider.
2. QUANDO o conjunto de CAs ainda não foi carregado, ENTÃO o sistema DEVE carregá-lo uma vez chamando `getCAs()` dos providers habilitados e publicá-lo para reuso.
3. O cache de cadeia por certificado (`CAManagerCache`) DEVE continuar funcionando como hoje.
4. O conjunto de CAs cacheado DEVE ter escopo consistente com o ambiente e os providers habilitados, SEM misturar configurações de produção e homologação.
5. QUANDO `CAManagerConfiguration.isCached()` é `false`, ENTÃO o sistema DEVE manter o comportamento atual (sem cache de CAs nem de cadeia).

### Requisito 2 — Política explícita de atualização das CAs

**User Story:** Como mantenedor, quero uma política de atualização definida, para controlar quando o conjunto de CAs é recarregado e como isso afeta cadeias já construídas.

#### Acceptance Criteria

1. PARA CAs embarcadas (classpath/JAR), o sistema DEVE carregar uma única vez por ciclo de vida do classloader enquanto a configuração permanecer estável.
2. O conjunto de CAs DEVE ter uma validade (TTL) configurável, com **default de 1 hora (3.600.000 ms)**. QUANDO o TTL expira, ENTÃO o próximo acesso DEVE recarregar e republicar o conjunto. O sistema DEVE suportar invalidação explícita independente do TTL.
   - OBSERVAÇÃO: com o conjunto consolidado único, o TTL recarrega todos os providers habilitados juntos (inclusive embarcados). O custo de recarregar embarcados é desprezível (leitura de classpath). O TTL cobre o risco de uma CA removida/não confiável permanecer em cache por tempo indefinido; a janela máxima de uso de uma CA removida é o TTL.
3. QUANDO o cache de CAs é invalidado ou atualizado, ENTÃO o cache de cadeia por certificado DEVE ser invalidado de forma consistente, para não reter cadeias construídas sobre CAs removidas ou não mais confiáveis.
4. A consulta ao hash remoto e eventual download do ZIP DEVE ocorrer no momento da carga/atualização do conjunto de CAs, e NÃO ser disparada pela chegada de cada certificado desconhecido.
5. Os providers online DEVEM respeitar `ConfigurationRepo.isOnline()`: QUANDO `isOnline()` for `false`, ENTÃO NÃO DEVEM consultar hash remoto nem baixar o ZIP, usando apenas artefatos locais.

### Requisito 3 — Reduzir o trabalho dentro do bloqueio global

**User Story:** Como operador, quero que validações cujo certificado já está em cache não fiquem bloqueadas por uma carga de CAs em andamento, para evitar contenção na JVM.

#### Acceptance Criteria

1. Leituras do conjunto de CAs já publicado DEVEM ser concorrentes, sem exigir o bloqueio global de `getCertificateChain()`.
2. QUANDO múltiplas threads detectam a necessidade de carregar/atualizar o conjunto de CAs, ENTÃO apenas UMA carga/atualização DEVE executar por vez (single-flight), evitando downloads duplicados.
3. Operações de rede e parse de ZIP NÃO DEVEM ocorrer dentro de um bloqueio compartilhado por todas as consultas de cadeia.
4. A publicação de um novo conjunto de CAs DEVE ser atômica: leitores veem o conjunto antigo completo ou o novo completo, nunca um estado parcial.
5. A segurança de concorrência dos caches (cadeia e CAs) DEVE ser preservada; consultas simultâneas ao mesmo certificado DEVEM continuar corretas.

### Requisito 4 — Tratar falhas e resultados parciais

**User Story:** Como mantenedor, quero que falhas temporárias de carregamento não sejam persistidas como conjunto válido, para não corromper o cache de CAs.

#### Acceptance Criteria

1. QUANDO a carga do conjunto de CAs falha (exceção ou resultado vazio por erro), ENTÃO o sistema NÃO DEVE publicar esse resultado como conjunto válido e duradouro.
2. QUANDO a atualização do conjunto de CAs falha E já existe um conjunto anterior válido, ENTÃO o sistema PODE continuar usando o conjunto anterior somente conforme política explícita de validade e confiança, registrando o erro.
3. QUANDO não há conjunto anterior E a carga falha, ENTÃO o sistema DEVE propagar o erro para o chamador (como hoje `CAManager` lança `CAManagerException` ao não construir a cadeia).
4. Um resultado parcial de um provider (ex: `getCAs()` que engole exceção e retorna lista incompleta) NÃO DEVE, por si só, ser tratado como conjunto completo e cacheável de forma permanente quando indicar falha detectável.

### Requisito 5 — Observabilidade e testes

**User Story:** Como operador, quero logs/métricas que distingam carga de CAs de hit/miss de cadeia, para diagnosticar latência e recargas.

#### Acceptance Criteria

1. O sistema DEVE registrar de forma distinguível: hit/miss do cache de cadeia por certificado; carga inicial e atualização do conjunto de CAs; duração do carregamento por provider; consulta remota de hash versus download do ZIP; falhas na construção da cadeia.
2. A suíte de testes DEVE cobrir: certificados distintos da mesma CA (uma única carga de CAs); concorrência (uma única carga sob N threads); atualização/invalidação do conjunto de CAs; recuperação após falha de carregamento.
3. Os testes DEVEM confirmar que, após a carga inicial, a validação de um novo certificado cuja cadeia seja atendida pelas CAs disponíveis NÃO provoca nova chamada a `getCAs()` de todos os providers.

## Fora de Escopo

- Desabilitar ou alterar validações de confiança, validade da assinatura ou revogação.
- Cache de dados de revogação (LCR).
- Alterar o formato dos artefatos (ZIP, .crt) ou as URLs dos repositórios.
- Mudar a interface pública `ProviderCA`.
