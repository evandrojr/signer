# Cache de CAs dos Providers - Design

## Overview

Hoje `CAManager.getCertificateChain()` só reaproveita trabalho via cache por certificado (`CAManagerCache`). Em todo *miss* de cadeia, o método coleta o conjunto de CAs chamando `getCAs()` de todos os providers:

```java
List<X509Certificate> allCAs = new ArrayList<>();
Collection<ProviderCA> providers = ProviderCAFactory.getInstance().factory();
for (ProviderCA provider : providers) {
    try {
        allCAs.addAll(provider.getCAs());
    } catch (Exception e) {
        LOGGER.warn(coreMessagesBundle.getString("error.no.ca", provider.getName()));
    }
}
```

Isso ocorre dentro do método `synchronized` do singleton `CAManager`, então rede e parse de ZIP acontecem sob o lock global.

A correção introduz um **cache de CAs** (`ProviderCACache`) que consolida `allCAs` uma única vez por escopo (ambiente + providers habilitados), publica o conjunto de forma atômica, serializa apenas a carga/atualização (single-flight) e mantém as leituras concorrentes fora do lock de construção de cadeia. Também corrige os providers online para respeitarem `ConfigurationRepo.isOnline()`.

A interface `ProviderCA` **não** muda. O cache de cadeia (`CAManagerCache`) continua existindo e passa a ser invalidado em conjunto quando o conjunto de CAs é invalidado/atualizado.

## Glossary

- **`allCAs`**: Conjunto consolidado de `X509Certificate` de todos os providers habilitados.
- **`ProviderCACache`**: Nova classe (singleton) que guarda `allCAs`, controla validade, single-flight e publicação atômica.
- **Escopo (`scopeKey`)**: String derivada do ambiente (`DisablingUtil`/`SIGNER_ENV`) e dos nomes dos providers habilitados. Muda de escopo ⇒ invalida o conjunto.
- **Publicação atômica**: `AtomicReference<CaSnapshot>` trocada por `set()`.
- **`CaSnapshot`**: Registro imutável com `{ List<X509Certificate> cas, String scopeKey, long loadedAtMillis }`.
- **Single-flight**: Um `ReentrantLock` dedicado à carga; leitores não o adquirem.
- **TTL**: Tempo de validade (ms) do snapshot. Default **3.600.000 ms (1 hora)**. `0`/negativo = sem expiração por tempo (apenas por escopo/invalidação explícita).

## Arquitetura

```
CAManager.getCertificateChain(cert)
  ├─ cache de cadeia (CAManagerCache) ── hit ──> retorna cadeia
  └─ miss
       └─ allCAs = ProviderCACache.getInstance().getCAs()   // fora do lock de rede
             ├─ snapshot válido (escopo + TTL) ─> retorna snapshot (lock-free read)
             └─ inválido ─> loadLock.lock()  (single-flight)
                   ├─ recheck snapshot (double-checked)
                   ├─ coleta getCAs() dos providers (rede/ZIP aqui)
                   ├─ se sucesso: publica novo CaSnapshot (AtomicReference.set)
                   │              e invalida CAManagerCache (cadeia) se escopo mudou
                   └─ se falha: mantém snapshot anterior OU propaga erro
       └─ constrói cadeia navegando allCAs  (lógica atual preservada)
```

### Mudança de concorrência em `CAManager`

Problema atual: `getCertificateChain()` é `synchronized` no singleton; rede ocorre sob o lock, bloqueando até consultas que teriam *hit* no cache de cadeia.

Design:
- A leitura do cache de cadeia e a leitura do snapshot de CAs **não** precisam do `synchronized` do método.
- A carga de CAs é serializada por `ProviderCACache.loadLock` (dedicado), não pelo lock do `CAManager`.
- `CAManagerCache` já é `synchronized` nos escritores; mantemos isso. A construção da cadeia em si (navegação + `verify`) não faz rede.

Decisão: **remover o `synchronized`** de `CAManager.getCertificateChain()` e delegar a serialização necessária ao `ProviderCACache` (carga) e ao `CAManagerCache` (escrita de cadeia). Leituras de cadeia/CAs ficam concorrentes.

> Nota de segurança de concorrência: `CAManagerCache` usa `HashMap` com escritores `synchronized` mas leitores sem sincronização (`getCachedCertificatesFor`, `getIsCAofCertificate`). Com o `synchronized` do método removido, leitores concorrentes de `HashMap` durante escrita são inseguros. O design troca os mapas de `CAManagerCache` por `ConcurrentHashMap` para permitir leitura concorrente segura sem o lock global.

## Componentes

### 1. `ProviderCACache` (nova classe em `core/.../ca/manager/`)

```java
public final class ProviderCACache {

    private static final ProviderCACache INSTANCE = new ProviderCACache();

    private final AtomicReference<CaSnapshot> snapshotRef = new AtomicReference<>();
    private final ReentrantLock loadLock = new ReentrantLock();

    // TTL do snapshot; default 1h (3600000 ms); 0 = sem expiração por tempo
    private volatile long ttlMillis = resolveTtlFromConfig();   // default 3_600_000L

    private ProviderCACache() {}

    public static ProviderCACache getInstance() { return INSTANCE; }

    /** Retorna o conjunto de CAs, carregando/atualizando se necessário. */
    public List<X509Certificate> getCAs() {
        String scope = currentScopeKey();
        CaSnapshot current = snapshotRef.get();
        if (isValid(current, scope)) {
            return current.cas();            // leitura lock-free
        }
        return loadAndPublish(scope);        // single-flight
    }

    private List<X509Certificate> loadAndPublish(String scope) {
        loadLock.lock();
        try {
            CaSnapshot current = snapshotRef.get();       // double-check
            if (isValid(current, scope)) {
                return current.cas();
            }
            boolean scopeChanged = current != null && !current.scopeKey().equals(scope);

            LoadResult loaded = collectFromProviders();   // rede/ZIP AQUI, sob loadLock
            if (loaded.usable()) {
                CaSnapshot fresh = new CaSnapshot(
                        List.copyOf(loaded.cas()), scope, System.currentTimeMillis());
                snapshotRef.set(fresh);                    // publicação atômica
                // invalida cache de cadeia quando o conjunto de CAs muda
                if (scopeChanged || current == null) {
                    CAManagerCache.getInstance().invalidate();
                }
                return fresh.cas();
            }
            // falha: política de resultado anterior
            if (current != null) {
                LOGGER.warn("Falha ao atualizar CAs; mantendo snapshot anterior.");
                return current.cas();
            }
            throw new CAManagerException(/* error.get.chain ou mensagem dedicada */);
        } finally {
            loadLock.unlock();
        }
    }

    public void invalidate() { snapshotRef.set(null); }

    private boolean isValid(CaSnapshot s, String scope) {
        if (s == null || !s.scopeKey().equals(scope)) return false;
        if (ttlMillis <= 0) return true;
        return (System.currentTimeMillis() - s.loadedAtMillis()) < ttlMillis;
    }
    // currentScopeKey(), collectFromProviders(), resolveTtlFromConfig() ...
}
```

`CaSnapshot` (record ou classe imutável):

```java
record CaSnapshot(List<X509Certificate> cas, String scopeKey, long loadedAtMillis) {}
```

`collectFromProviders()` reutiliza exatamente o laço atual de `CAManager` (incluindo o `catch` por provider que loga `error.no.ca`), mas devolve um `LoadResult` que distingue sucesso de falha total:

- `usable()` = `true` quando ao menos um provider retornou CAs sem erro detectável.
- Se **todos** os providers falharam (exceções) ou o conjunto ficou vazio por erro, `usable()` = `false` ⇒ não publica.

### 2. `currentScopeKey()`

Deriva o escopo do ambiente e dos providers habilitados:

```java
private String currentScopeKey() {
    // ex.: "env=prod;providers=[ICPBrasilOnLineSerpro,ICPBrasilUserHome,SerproNeoSigner]"
    List<String> names = new ArrayList<>();
    for (ProviderCA p : ProviderCAFactory.getInstance().factory()) {
        if (!isProviderDisabled(p)) names.add(p.getClass().getSimpleName());
    }
    Collections.sort(names);
    return "env=" + DisablingUtil.currentEnvLabel() + ";providers=" + names;
}
```

Isso garante o AC "sem misturar produção e homologação": mudar `SIGNER_ENV` ou habilitar/desabilitar uma cadeia muda o `scopeKey` e força recarga.

### 3. Ajuste em `CAManager.getCertificateChain()`

- Remover `synchronized` do método.
- Substituir o laço que coleta `allCAs` por:

```java
List<X509Certificate> allCAs = ProviderCACache.getInstance().getCAs();
```

- Manter integralmente a lógica de navegação da cadeia (match por `X500Principal`, fallback por CN, `isCAofCertificate`, detecção de loop, montagem de `result`, log de cadeia parcial, `CAManagerException`).
- Manter a escrita no cache de cadeia: `CAManagerCache.getInstance().addCertificate(certificate, result)`.

### 4. `CAManagerCache` → `ConcurrentHashMap`

Trocar:

```java
private Map<String, Collection<X509Certificate>> cachedCertificates = new HashMap<>();
private Map<String, Boolean> isCAofCertificate = new HashMap<>();
```

por `ConcurrentHashMap`. Os métodos `addCertificate`/`setIsCAofCertificate` podem deixar de ser `synchronized` (o `ConcurrentHashMap` cobre a atomicidade de `put`). `invalidate()` continua limpando ambos os mapas. Isso torna as leituras concorrentes seguras depois de remover o `synchronized` do `CAManager`.

### 5. Providers online respeitam `isOnline()`

Em `ICPBrasilOnLineSerproProviderCA.getCAs()` e `ICPBrasilOnLineITIProviderCA.getCAs()`, antes de consultar hash remoto / baixar ZIP:

```java
if (!ConfigurationRepo.getInstance().isOnline()) {
    LOGGER.debug("Modo offline: usando ZIP local sem consulta remota.");
    Path pathZip = ICPBrasilUserHomeProviderCA.FULL_PATH_ZIP;
    if (Files.exists(pathZip)) {
        try (InputStream in = new FileInputStream(pathZip.toString())) {
            return getFromZip(in);
        }
    }
    return new HashSet<>();
}
// ... fluxo online atual (consulta hash, compara, baixa se necessário)
```

Isso atende ao Requisito 2.5 sem alterar o comportamento online padrão (default `isOnline()==true`).

## Fluxos

### Carga inicial (primeiro certificado)
1. `getCertificateChain(certA)` → cache de cadeia miss.
2. `ProviderCACache.getCAs()` → snapshot nulo → `loadLock` → `collectFromProviders()` (rede/ZIP) → publica snapshot → invalida cache de cadeia (primeira vez, no-op prático).
3. Constrói e cacheia cadeia de `certA`.

### Segundo certificado distinto, mesma CA (alvo principal)
1. `getCertificateChain(certB)` → cache de cadeia miss.
2. `ProviderCACache.getCAs()` → snapshot válido (mesmo escopo, TTL ok) → retorna sem chamar `getCAs()` de nenhum provider. **Mensagem do NeoSigner NÃO reaparece.**
3. Constrói e cacheia cadeia de `certB`.

### Concorrência (N threads, certificados variados, snapshot frio)
1. Todas chamam `ProviderCACache.getCAs()`; snapshot nulo.
2. Uma adquire `loadLock` e carrega; as demais bloqueiam só na carga.
3. Após publicação, double-check faz as demais retornarem o snapshot sem recarregar. **Uma carga por provider.**

### Atualização por TTL (online) / invalidação explícita
1. Snapshot expira (TTL) ou `invalidate()` é chamado.
2. Próximo `getCAs()` recarrega sob `loadLock`, republica e invalida o cache de cadeia (escopo igual mas dados renovados → invalida para não reter cadeias sobre CAs removidas).

### Falha de atualização com snapshot anterior
1. `collectFromProviders()` retorna `usable()==false`.
2. Mantém snapshot anterior, loga warning; não corrompe o cache. (Requisito 4.2)

## Expected Behavior / Preservation

Comportamentos **inalterados**:
- Algoritmo de construção da cadeia (match de principals, fallback CN, `isCAofCertificate`, loop guard, log de cadeia parcial, `CAManagerException` quando não fecha na raiz).
- Semântica de `CAManagerConfiguration.isCached()==false` (sem cache algum).
- Interface `ProviderCA` e as URLs/artefatos dos providers.
- Validações de confiança/validade/revogação e o repositório de LCR.
- `SerproNeoSignerProviderCA.getCAs()` mantém a seleção prod/homolog via `DisablingUtil`; a mensagem de log permanece, mas passa a ocorrer apenas na carga do snapshot.

Comportamentos **novos/alterados**:
- `allCAs` reaproveitado entre certificados (Req 1).
- `getCertificateChain()` deixa de ser `synchronized`; serialização movida para `ProviderCACache.loadLock` e `ConcurrentHashMap` em `CAManagerCache` (Req 3).
- Providers online respeitam `isOnline()` (Req 2.5).
- Invalidação conjunta cache de CAs + cache de cadeia (Req 2.3).

## Configuração

Novas chaves (padrão do projeto: env var + system property), resolvidas em `resolveTtlFromConfig()`:

- `SIGNER_CAMANAGER_CA_TTL_MILLIS` / `signer.camanager.ca.ttl.millis` — TTL do snapshot de CAs. Default **3600000** (1 hora). `0` ou negativo desliga a expiração por tempo (atualização só por mudança de escopo ou invalidação explícita). A mudança de escopo (ambiente/providers habilitados) sempre força recarga, independente do TTL.

Precedência (igual a `ConfigurationRepo`): env var > system property > default.

## Estratégia de Testes

Testes em `core` (módulo de `CAManager`), com um `ProviderCA` de teste contando chamadas a `getCAs()`:

1. **Mesma CA, certificados distintos**: 2+ certificados da mesma cadeia ⇒ `getCAs()` chamado 1x por provider.
2. **Concorrência**: N threads, snapshot frio ⇒ `getCAs()` chamado 1x por provider (contador atômico).
3. **Invalidação/atualização**: após `invalidate()`, próximo acesso recarrega 1x e cache de cadeia é limpo.
4. **Falha de carga sem snapshot anterior**: providers lançam ⇒ `CAManagerException` propagada; nada publicado.
5. **Falha de atualização com snapshot anterior**: mantém snapshot anterior.
6. **Escopo**: mudança de ambiente/providers habilitados força recarga e invalida cache de cadeia.
7. **`isOnline()==false`**: providers online não fazem consulta remota (mock/registro de que `Downloads` não é chamado).

## Riscos e Mitigações

- **Leitura concorrente de `HashMap`**: mitigada migrando `CAManagerCache` para `ConcurrentHashMap` antes de remover o `synchronized`.
- **Snapshot imutável x providers que retornam coleções mutáveis**: `List.copyOf` ao publicar.
- **CA removida de repositório permanecendo em cadeia cacheada**: invalidação conjunta do cache de cadeia na atualização de CAs.
- **Falha parcial publicada como válida**: `LoadResult.usable()` distingue sucesso de falha total; política de "anterior válido" explícita.
