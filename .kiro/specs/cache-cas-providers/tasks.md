# Cache de CAs dos Providers - Tasks

## 1. Cache de cadeia seguro para concorrência
- [x] 1.1 Migrar `CAManagerCache` de `HashMap` para `ConcurrentHashMap` em `cachedCertificates` e `isCAofCertificate`.
- [x] 1.2 Manter `invalidate()` limpando ambos os mapas; remover `synchronized` redundante dos escritores (atomicidade coberta pelo `ConcurrentHashMap`).
- _Requisitos: 3.5_

## 2. ProviderCACache (novo)
- [x] 2.1 Criar `core/.../ca/manager/ProviderCACache.java` (singleton) com `AtomicReference<CaSnapshot>` e `ReentrantLock loadLock`.
- [x] 2.2 `CaSnapshot` imutável `{ List<X509Certificate> cas, String scopeKey, long loadedAtMillis }`.
- [x] 2.3 `resolveTtlFromConfig()` lendo `SIGNER_CAMANAGER_CA_TTL_MILLIS` / `signer.camanager.ca.ttl.millis`, default 3600000.
- [x] 2.4 `currentScopeKey()` a partir de `DisablingUtil.getEnvironment()` + nomes de classe dos providers habilitados (ordenados).
- [x] 2.5 `collectFromProviders()` reutilizando o laço atual de `CAManager` (catch por provider com `error.no.ca`), devolvendo `LoadResult` com `usable()` (falso se todos falharam/vazio por erro).
- [x] 2.6 `getCAs()`: leitura lock-free do snapshot válido; `loadAndPublish()` com single-flight, double-check, publicação atômica e invalidação do cache de cadeia em mudança de escopo/primeira carga.
- [x] 2.7 Política de falha: sem snapshot anterior ⇒ `CAManagerException`; com anterior ⇒ mantém anterior + warning.
- [x] 2.8 `invalidate()` zera o snapshot.
- _Requisitos: 1.1, 1.2, 1.4, 2.1, 2.2, 2.3, 2.4, 3.1, 3.2, 3.3, 3.4, 4.1, 4.2, 4.3, 4.4_

## 3. Integração no CAManager
- [x] 3.1 Remover `synchronized` de `getCertificateChain(X509Certificate)`.
- [x] 3.2 Substituir o laço de coleta de `allCAs` por `ProviderCACache.getInstance().getCAs()`.
- [x] 3.3 Preservar integralmente navegação de cadeia, logs e `CAManagerException`.
- [x] 3.4 Respeitar `CAManagerConfiguration.isCached()==false` (sem cache de CAs nem de cadeia).
- _Requisitos: 1.1, 1.2, 1.3, 1.5, 3.1_

## 4. Providers online respeitam isOnline()
- [x] 4.1 Em `ICPBrasilOnLineSerproProviderCA.getCAs()`, quando `ConfigurationRepo.getInstance().isOnline()==false`, usar só ZIP local (sem hash remoto/download). ITI herda.
- _Requisitos: 2.5_

## 5. Observabilidade
- [x] 5.1 Logs distinguindo: carga/atualização de CAs, duração por provider, hash remoto vs download ZIP, hit/miss de cadeia, falha de construção.
- _Requisitos: 5.1_

## 6. Testes
- [x] 6.1 Teste com `ProviderCA` de teste contando `getCAs()`: certificados distintos mesma CA ⇒ 1 carga por provider.
- [x] 6.2 Concorrência: N threads, snapshot frio ⇒ 1 carga por provider.
- [x] 6.3 Invalidação/atualização recarrega 1x e limpa cache de cadeia.
- [x] 6.4 Falha sem snapshot anterior ⇒ `CAManagerException`; com anterior ⇒ mantém anterior.
- [x] 6.5 Mudança de escopo força recarga.
- _Requisitos: 5.2, 5.3_

## 7. Verificação de build e no eprocesso
- [x] 7.1 `mvn -pl core -am install` no signer; resolver erros de compilação/teste.
- [x] 7.2 `mvn install` dos módulos de chain afetados.
- [x] 7.3 Apontar `teste-eprocesso-signer` para `4.6.3-SNAPSHOT` e rodar `FluxoEprocessoTest`, confirmando 1 carga por provider (mensagem do NeoSigner uma única vez) no loop de 100 alternando dois assinantes.
- _Requisitos: 5.3_
