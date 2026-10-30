# Demoiselle Signer

Biblioteca Java para assinatura digital baseada nos padrões ICP-Brasil, desenvolvida pelo [SERPRO](https://www.serpro.gov.br).

Suporta os formatos **CAdES**, **XAdES** e **PAdES** conforme as políticas do ITI (Instituto Nacional de Tecnologia da Informação).

[![License: LGPL v3](https://img.shields.io/badge/License-LGPL%20v3-blue.svg)](https://www.gnu.org/licenses/lgpl-3.0)

---

## Módulos

| Módulo | Descrição |
|---|---|
| `core` | Infraestrutura base: gerenciamento de cadeias CA, downloads, repositório de CRL |
| `cryptography` | Utilitários criptográficos |
| `chain-icp-brasil` | Cadeia de ACs ICP-Brasil (produção) — carregada automaticamente via ServiceLoader |
| `chain-icp-brasil-homolog` | Cadeia de ACs ICP-Brasil (homologação) — **desativada por padrão (opt-in)**, veja [Ativação/desativação de cadeias](#ativaçãodesativação-de-cadeias) |
| `chain-iti` | Provider alternativo de cadeia via ITI online |
| `chain-serpro-neosigner` | Provider de cadeia via mirror SERPRO |
| `policy-engine` | Motor de políticas de assinatura — baixa e valida LPAs |
| `policy-impl-cades` | Assinatura CAdES (CMS Advanced Electronic Signatures) |
| `policy-impl-xades` | Assinatura XAdES (XML Advanced Electronic Signatures) |
| `policy-impl-pades` | Assinatura PAdES (PDF Advanced Electronic Signatures) |
| `timestamp` | Carimbo de tempo (RFC 3161) |
| `signer-xmldsig` | Assinatura XMLDSig básica |

---

## Dependência Maven

Adicione o módulo desejado ao seu `pom.xml`. Para assinatura CAdES:

```xml
<dependency>
    <groupId>org.demoiselle.signer</groupId>
    <artifactId>policy-impl-cades</artifactId>
    <version>4.6.2</version>
</dependency>
```

A cadeia ICP-Brasil é carregada automaticamente se `chain-icp-brasil` estiver no classpath:

```xml
<dependency>
    <groupId>org.demoiselle.signer</groupId>
    <artifactId>chain-icp-brasil</artifactId>
    <version>4.6.2</version>
</dependency>
```

Artefatos disponíveis no [Maven Central](https://central.sonatype.com/search?q=org.demoiselle.signer).

---

## Build

Requer Java 8 e Maven 3.9+.

```bash
mvn clean install
```

Para gerar uma nova versão, use o script:

```bash
./gerar-versao.sh
```

---

## Configuração

As principais configurações são feitas via variável de ambiente ou system property:

| Variável de ambiente | System property | Padrão | Descrição |
|---|---|---|---|
| `SIGNER_CA_CHAIN_CONNECTION_TIMEOUT` | `signer.ca.chain.connection.timeout` | `30000` | Timeout (ms) para download de cadeias CA |
| `SIGNER_CRL_CONNECTION_TIMEOUT` | `signer.crl.connection.timeout` | `5000` | Timeout (ms) para download de CRLs |
| `SIGNER_REPOSITORY_ONLINE` | `signer.repository.online` | `true` | Habilita/desabilita consulta online de CRLs e das cadeias CA online (hash remoto / download do ZIP) |
| `SIGNER_CAMANAGER_CACHED` | `signer.camanager.cached` | `true` | Habilita o cache do `CAManager` (cadeia por certificado e conjunto de CAs) |
| `SIGNER_CAMANAGER_CA_TTL_MILLIS` | `signer.camanager.ca.ttl.millis` | `3600000` | Validade (ms) do cache do conjunto de CAs dos providers. `0` ou negativo desliga a expiração por tempo |
| `SIGNER_PROXY_HOST` | `signer.proxy.host` | — | Host do proxy |
| `SIGNER_PROXY_PORT` | `signer.proxy.port` | — | Porta do proxy |

### Ativação/desativação de cadeias

O modelo de configuração é **positivo (baseado em habilitar)** e em camadas, com a seguinte ordem de precedência:

1. **Override por cadeia** `SIGNER_ENABLE_CHAIN_<NOME_DA_CADEIA>` — palavra final para aquela cadeia.
2. **Perfil de ambiente** `SIGNER_ENV`.
3. **Padrão seguro** — cadeias de produção carregadas; cadeias de homologação **não** (opt-in).

> 🔒 **Cadeias de homologação são opt-in por segurança.** As cadeias de homologação (`chain-icp-brasil-homolog`, `chain-iti-homolog` e a sub-cadeia HOM do NeoSigner) só carregam quando explicitamente habilitadas. Certificados de homologação vêm de ACs de teste; se carregados em produção, poderiam validar como legítima uma assinatura forjada com certificado de homologação.

#### Perfil global `SIGNER_ENV`

| Valor de `SIGNER_ENV` | Cadeias de produção | Cadeias de homologação |
|---|---|---|
| *(não definido)* / `prod` / `production` | carregadas | **não** carregadas |
| `hom` / `homolog` | não carregadas | carregadas |
| `both` (alias: `pro,hom` / `hom,pro`) | carregadas | carregadas |

```bash
# Produção (padrão): só cadeias de produção
export SIGNER_ENV=prod

# Homologação: só cadeias de homologação
export SIGNER_ENV=hom

# Produção + homologação juntas
export SIGNER_ENV=both
```

#### Override por cadeia `SIGNER_ENABLE_CHAIN_<NOME>`

Habilita (`true`) ou desliga (`false`) **uma cadeia específica**, sobrepondo o perfil — nos **dois sentidos**. `<NOME>` é o nome do módulo em maiúsculas com hífens trocados por sublinhados.

| Variável de ambiente | Módulo / cadeia | Padrão |
|---|---|---|
| `SIGNER_ENABLE_CHAIN_ICP_BRASIL` | `chain-icp-brasil` (produção, todas as fontes) | Habilitada |
| `SIGNER_ENABLE_CHAIN_ICP_BRASIL_HOMOLOG` | `chain-icp-brasil-homolog` (homologação) | **Desabilitada (opt-in)** |
| `SIGNER_ENABLE_CHAIN_ITI_HOMOLOG` | `chain-iti-homolog` (homologação) | **Desabilitada (opt-in)** |
| `SIGNER_ENABLE_CHAIN_SERPRO_NEOSIGNER` | `chain-serpro-neosigner` (provider completo) | Habilitada |
| `SIGNER_ENABLE_CHAIN_SERPRO_NEOSIGNER_PROD` | Sub-cadeia de produção do NeoSigner | Habilitada |
| `SIGNER_ENABLE_CHAIN_SERPRO_NEOSIGNER_HOMOLOG` | Sub-cadeia de homologação do NeoSigner | **Desabilitada (opt-in)** |

O override funciona em qualquer direção, independentemente do tipo da cadeia:

```bash
# Em produção, também carregar a homologação do ICP-Brasil
export SIGNER_ENV=prod
export SIGNER_ENABLE_CHAIN_ICP_BRASIL_HOMOLOG=true

# Em homologação, também carregar uma cadeia de produção específica
export SIGNER_ENV=hom
export SIGNER_ENABLE_CHAIN_ICP_BRASIL=true

# Desligar uma cadeia de produção específica mesmo em ambiente de produção
export SIGNER_ENABLE_CHAIN_ICP_BRASIL=false
```

> **Nota**: variáveis de ambiente são lidas no momento do carregamento das cadeias e não podem ser alteradas em tempo de execução pelo código Java — defina-as antes de iniciar a JVM.

> ⚠️ **Atenção**: as cadeias de homologação são opt-in justamente por conterem ACs de teste que podem validar certificados falsos. Só as habilite em ambientes de teste/homologação, nunca em produção.

### Cache de cadeias e de CAs

O `CAManager` mantém **dois níveis de cache independentes**, ambos ativos quando `SIGNER_CAMANAGER_CACHED=true` (padrão):

1. **Cache de cadeia por certificado** (`CAManagerCache`): guarda a cadeia já construída para cada certificado final (chave: Subject DN + número de série) e o resultado das verificações de assinatura entre certificados. Evita reconstruir a cadeia do mesmo signatário repetidamente.
2. **Cache do conjunto de CAs dos providers** (`ProviderCACache`): guarda a união das CAs retornadas por `getCAs()` de **todos os providers habilitados** em um único *snapshot*. Assim, validar um certificado **novo** cuja cadeia já seja atendida pelas CAs disponíveis **não** dispara nova leitura/consulta a todos os providers (sem ler ZIP do disco nem consultar hash/baixar os repositórios online a cada novo signatário).

**Por que dois níveis**: antes existia apenas o cache de cadeia. Cada certificado inédito recarregava `getCAs()` de todos os providers (I/O de disco e de rede). Em um ambiente com muitos signatários distintos, isso provocava recargas recorrentes dos repositórios de CAs. Com o cache de CAs, a carga ocorre uma vez por *snapshot* e é reaproveitada por todos os signatários.

**Validade (TTL)**: o *snapshot* de CAs expira pelo TTL configurável em `SIGNER_CAMANAGER_CA_TTL_MILLIS` / `signer.camanager.ca.ttl.millis` (padrão **1 hora**). Ao expirar, a próxima consulta recarrega e republica o conjunto. `0` ou negativo desliga a expiração por tempo (atualização só por mudança de escopo ou invalidação explícita).

> **Janela de confiança**: enquanto o *snapshot* é válido, uma CA que tenha sido removida/deixado de ser confiável ainda pode ser usada até o TTL expirar (ou até invalidação explícita). O padrão de 1 hora limita essa janela. Isso **não** afeta a validação de revogação (CRL/OCSP), que continua independente.

**Escopo**: o *snapshot* é vinculado ao ambiente (`SIGNER_ENV`) e ao conjunto de providers habilitados. Mudar o perfil ou habilitar/desabilitar uma cadeia força a recarga, evitando misturar CAs de produção e de homologação.

**Concorrência**: a leitura do *snapshot* é lock-free; apenas a (re)carga é serializada (uma carga por vez, sem downloads duplicados). As operações de rede/ZIP ocorrem fora do bloqueio compartilhado pelas consultas de cadeia.

**Invalidação explícita** (por exemplo, após atualizar manualmente os repositórios de CAs):

```java
// invalida o conjunto de CAs (força recarga na próxima consulta)
org.demoiselle.signer.core.ca.manager.ProviderCACache.getInstance().invalidate();

// invalida o cache de cadeia por certificado
org.demoiselle.signer.core.ca.manager.CAManagerCache.getInstance().invalidate();
```

> A invalidação do conjunto de CAs também limpa o cache de cadeia por certificado automaticamente a cada (re)publicação, para não reaproveitar cadeias construídas sobre CAs que deixaram de existir.

**Modo offline**: com `SIGNER_REPOSITORY_ONLINE=false` (`ConfigurationRepo.setOnline(false)`), os providers online (`ICPBrasilOnLineSerproProviderCA`, `ICPBrasilOnLineITIProviderCA`) não consultam o hash remoto nem baixam o ZIP — usam apenas o artefato local já presente no *user home*.

---

## Publicação (Deploy)

### Pré-requisitos

- **settings.xml** configurado com server `ossrh` (usuário/token do [central.sonatype.com](https://central.sonatype.com))
- **GPG** key configurada para assinatura dos artefatos
- Java 8+ e Maven 3.9+

> ⚠️ **GPG**: configure `gpg.keyname`, `gpg.passphrase` e `gpg.arg=--pinentry-mode/loopback` no profile do `settings.xml`. **Não** passe `-Dgpg.passphrase=""` na linha de comando — isso sobrescreve a passphrase do `settings.xml` e a assinatura falha com `gpg: Frase secreta não fornecida`.

### SNAPSHOT

Publica no repositório de SNAPSHOTs (`https://central.sonatype.com/repository/maven-snapshots/`):

```bash
mvn clean deploy -Dmaven.test.skip=true -Dmaven.javadoc.skip=true -B
```

### Release (Maven Central)

> ⚠️ A versão no POM **não pode** conter `-SNAPSHOT`.

```bash
mvn clean deploy -Dmaven.test.skip=true -Dmaven.javadoc.skip=true -B \
    -P release
```

O profile `release` ativa o `central-publishing-maven-plugin` com `<extensions>true</extensions>`, que faz o upload e publish para o Maven Central.

### Publicador Go

O programa [`publicador.go`](publicador.go) automatiza a publicação completa:

```bash
# SNAPSHOT
go run publicador.go

# Release
go run publicador.go -release
```

Ele executa `mvn deploy` no reactor todo, com retry automático (até 20 tentativas com intervalo de 15s) e validação pós-publicação via consulta ao repositório.

#### Verificar publicação

Verifica se todos os módulos estão publicados no servidor e gera um relatório detalhado:

```bash
# Verificar SNAPSHOTs
go run publicador.go -validar

# Verificar releases no Maven Central
go run publicador.go -validar -release
```

O relatório mostra por módulo:
- ✅ Status geral (publicado/não publicado)
- 📦 Versão e número do build
- 📋 Arquivos publicados (pom, jar, sources.jar, javadoc.jar, assinaturas .asc) com status individual

## Release Notes

- [4.6.2](release-notes/4.6.2.md)

---

## Licença

[GNU Lesser General Public License v3](License.txt) — SERPRO
