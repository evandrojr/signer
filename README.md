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
| `chain-icp-brasil-homolog` | Cadeia de ACs ICP-Brasil (homologação) |
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
    <version>4.6.1</version>
</dependency>
```

A cadeia ICP-Brasil é carregada automaticamente se `chain-icp-brasil` estiver no classpath:

```xml
<dependency>
    <groupId>org.demoiselle.signer</groupId>
    <artifactId>chain-icp-brasil</artifactId>
    <version>4.6.1</version>
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
| `SIGNER_REPOSITORY_ONLINE` | `signer.repository.online` | `true` | Habilita/desabilita consulta online de CRLs |
| `SIGNER_PROXY_HOST` | `signer.proxy.host` | — | Host do proxy |
| `SIGNER_PROXY_PORT` | `signer.proxy.port` | — | Porta do proxy |

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

- [4.6.1](release-notes/4.6.1.md)

---

## Licença

[GNU Lesser General Public License v3](License.txt) — SERPRO
