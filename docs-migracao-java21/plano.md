# Plano de Migração: Java 7 para Java 21

## Demoiselle Signer - Versão 4.5.0

**⚠️ ATUALIZAÇÃO**: Código atualizado para versão 4.5.0 em 2026-01-23

---

## Status do Projeto

- **Versão Atual**: 4.5.0 (Released)
- **Java Atual**: 1.7 (JDK 7) ⚠️ **SEM MUDANÇA**
- **Java Destino**: 21 (LTS)
- **Total de Módulos**: 13
- **Total de Arquivos Java**: 350 (+2 desde análise anterior)
- **Testes Existentes**: 21 (+2 desde análise anterior)

---

## ⚠️ ANÁLISE DA VERSÃO 4.5.0

### O que mudou na 4.5.0:
- ✅ Versão bumped para 4.5.0
- ✅ Suporte a token DxToken no Linux e MacOS (#431)
- ✅ Correções de assinatura XML
- ✅ Suporte a assinatura de hash com carimbo (#432)
- ✅ Configuração para novo Maven Central (Sonatype)
- ✅ Adição de desenvolvedor Evandro Magalhães

### ❌ O que NÃO mudou:
- ❌ **Java version: AINDA É 1.7** (pom.xml linha 113)
- ❌ **Bug PKCS#11: NÃO CORRIGIDO** (DriverKeyStoreLoader.java linha 130)
- ❌ **Bug getSubjectAlternativeNames: NÃO CORRIGIDO** (CertificateExtra.java linha 83)
- ❌ **APIs sun.security.pkcs11: AINDA USADAS**
- ❌ **Dependências: MESMAS VERSÕES** (BouncyCastle 1.62, Log4j 2.11.2)

**CONCLUSÃO**: A versão 4.5.0 **NÃO RESOLVE** os problemas de compatibilidade com Java 21. Os dois bugs críticos identificados **PERMANECEM PRESENTES**.

---

## ✅ Etapas Executadas

- [x] **1. Instalação do Java 21**
  - SDK: OpenJDK 21.0.9 (Temurin)
  - Instalado via sdkman
  - Configurado como versão padrão
  - Data: 2026-01-23

---

## 📋 Plano de Migração

### Fase 1: Preparação e Análise (Atual)

- [x] 1.1. Instalar Java 21 usando sdkman
- [ ] 1.2. Análise de dependências e compatibilidade
  - [ ] Verificar versões do BouncyCastle (atualmente 1.62)
  - [ ] Verificar versões do Log4j (atualmente 2.11.2)
  - [ ] Analisar dependências do JAXB
  - [ ] Identificar APIs removidas/depreciadas
- [ ] 1.3. Compilação inicial com Java 21
  - [ ] Ajustar configuração do Maven
  - [ ] Resolver erros de compilação
  - [ ] Documentar warnings e depreciações

### Fase 2: Correção de Bugs Críticos - Java 9+

#### 2.1. Bug #1: getSubjectAlternativeNames (Java 19+)

**Problema Identificado**: O método `X509Certificate.getSubjectAlternativeNames()` mudou de comportamento no Java 19+, retornando listas com até 4 elementos em casos de `otherName`, enquanto o código assume exatamente 2 elementos.

**Arquivo Afetado**: `core/src/main/java/org/demoiselle/signer/core/extension/CertificateExtra.java`

- [ ] 2.1.1. Criar teste unitário para o bug
  - [ ] Criar certificado de teste com otherName
  - [ ] Reproduzir a falha com Java 21
  - [ ] Validar comportamento correto após correção
  
- [ ] 2.1.2. Implementar correção em CertificateExtra.java
  - [ ] Remover validação rígida de `list.size() != 2`
  - [ ] Implementar tratamento para listas com 2, 3 ou 4 elementos
  - [ ] Implementar código alternativo se necessário
  
- [ ] 2.1.3. Validar correção
  - [ ] Executar testes unitários
  - [ ] Validar com certificados ICP-Brasil reais
  - [ ] Testar com Java 8, 11, 17 e 21

#### 2.2. Bug #2: SunPKCS11 - Acesso a Tokens/SmartCards (Java 9+)

**⚠️ PROBLEMA CRÍTICO IDENTIFICADO**: A classe `sun.security.pkcs11.SunPKCS11` mudou drasticamente no Java 9+:

**Mudanças no Java 9+**:
1. **Construtor removido**: `SunPKCS11(InputStream)` e `SunPKCS11(String)` não existem mais
2. **Método login removido**: `login(Subject, CallbackHandler)` não existe mais
3. **Nova API**: Deve-se usar `Provider.configure(String)` no Java 9+

**Arquivos Afetados**:
- `core/src/main/java/org/demoiselle/signer/core/keystore/loader/implementation/DriverKeyStoreLoader.java` (linhas 130-137, 170-176, 248)
- `core/src/main/java/org/demoiselle/signer/core/keystore/loader/implementation/PKCS11Logout.java` (linha 46, 56-57)

**Uso de APIs Internas Deprecadas**:
- Linha 46 PKCS11Logout.java: `import sun.security.pkcs11.SunPKCS11;`
- Linha 130 DriverKeyStoreLoader.java: `Class.forName("sun.security.pkcs11.SunPKCS11")`
- Linha 248 DriverKeyStoreLoader.java: `new sun.security.pkcs11.SunPKCS11(...)`

**Impacto**: 
- ❌ Código atual **NÃO FUNCIONA** no Java 9+
- ❌ Impossível usar tokens/smartcards (certificados A3) no Java 21
- 🔥 **BLOQUEADOR TOTAL** para migração

**Solução Necessária**:

- [ ] 2.2.1. Refatorar DriverKeyStoreLoader.java
  - [ ] Detectar versão do Java em runtime
  - [ ] Implementar código condicional para Java 8 vs Java 9+
  - [ ] Java 9+: Usar `Provider.configure(String configPath)`
  - [ ] Java 9+: Remover chamadas ao método `login()` (obsoleto)
  - [ ] Criar arquivo de configuração temporário se necessário
  - [ ] Testar com tokens reais (SafeNet, Gemalto, etc.)

- [ ] 2.2.2. Refatorar PKCS11Logout.java
  - [ ] Java 9+: Usar `Security.removeProvider(providerName)`
  - [ ] Java 9+: Alternativa para logout (pode não ser necessário)
  - [ ] Manter compatibilidade com Java 8 se possível

- [ ] 2.2.3. Criar abstração de compatibilidade
  - [ ] Criar interface `PKCS11ProviderFactory`
  - [ ] Implementação Java8PKCS11Provider (código atual)
  - [ ] Implementação Java9PKCS11Provider (nova API)
  - [ ] Factory detecta versão e usa implementação apropriada

- [ ] 2.2.4. Testes extensivos com tokens
  - [ ] Certificados A3 em tokens USB
  - [ ] SmartCards
  - [ ] Diferentes fabricantes (SafeNet, Gemalto, Watchdata)
  - [ ] Validar em Java 8, 11, 17 e 21

**Exemplo de Código para Java 9+**:
```java
// ANTES (Java 8):
Provider p = new sun.security.pkcs11.SunPKCS11(new ByteArrayInputStream(config.getBytes()));

// DEPOIS (Java 9+):
Provider template = Security.getProvider("SunPKCS11");
Provider p = template.configure(configFilePath);
```

**Referências**:
- [JEP 229: Create PKCS12 Keystores by Default](https://openjdk.org/jeps/229)
- [JDK-8168469: New API for PKCS#11 provider configuration](https://bugs.openjdk.org/browse/JDK-8168469)

### Fase 3: Atualização de POMs e Configurações Maven

- [ ] 3.1. Atualizar pom.xml raiz (build)
  - [ ] Alterar `java.version` de 1.7 para 21
  - [ ] Alterar `maven.compiler.source` de 1.7 para 21
  - [ ] Alterar `maven.compiler.target` de 1.7 para 21
  - [ ] Atualizar maven-compiler-plugin para versão compatível (3.11+)
  - [ ] Atualizar maven-javadoc-plugin para versão compatível

- [ ] 3.2. Atualizar bom/pom.xml
  - [ ] Atualizar propriedades de versão do Java
  - [ ] Atualizar referências a Java 7 docs

- [ ] 3.3. Atualizar parent/pom.xml
  - [ ] Revisar Bundle-RequiredExecutionEnvironment no MANIFEST
  - [ ] Atualizar de JavaSE-1.6, JavaSE-1.7 para JavaSE-21

### Fase 4: Atualização de Dependências

- [ ] 4.1. BouncyCastle
  - [ ] Atualizar de 1.62 para versão mais recente (1.70+)
  - [ ] Validar compatibilidade com Java 21
  - [ ] Verificar breaking changes

- [ ] 4.2. Log4j
  - [ ] Atualizar de 2.11.2 para 2.20.0+ (correção de vulnerabilidades)
  - [ ] Validar configurações
  - [ ] Atualizar slf4j se necessário

- [ ] 4.3. JAXB
  - [ ] Manter dependências explícitas (removido do JDK 11+)
  - [ ] Atualizar versões para compatibilidade com Java 21
  - [ ] Verificar javax.xml.bind vs jakarta.xml.bind

- [ ] 4.4. JUnit
  - [ ] Considerar migração de JUnit 4.13.1 para JUnit 5 (Jupiter)
  - [ ] Atualizar testes se necessário

### Fase 5: Desenvolvimento de Testes

#### 5.1. Testes Unitários

- [ ] 5.1.1. Core Module
  - [ ] Testes para CertificateExtra (bug crítico)
  - [ ] Testes de extensões de certificados
  - [ ] Testes de OIDs ICP-Brasil
  
- [ ] 5.1.2. Cryptography Module
  - [ ] Testes de assinatura digital
  - [ ] Testes de verificação
  - [ ] Testes de algoritmos

- [ ] 5.1.3. Policy Modules (CAdES, XAdES, PAdES)
  - [ ] Testes de políticas de assinatura
  - [ ] Testes de validação
  
- [ ] 5.1.4. Timestamp Module
  - [ ] Testes de carimbo de tempo
  - [ ] Testes de conexão com TSA

- [ ] 5.1.5. Chain Modules
  - [ ] Testes de cadeias ICP-Brasil
  - [ ] Testes de validação de certificados

**Meta**: Aumentar cobertura de testes de 19 para pelo menos 100+ testes

#### 5.2. Testes de Integração

- [ ] 5.2.1. Configurar testador-ws
  - [ ] Documentar uso do testador-ws (Go)
  - [ ] Criar cenários de teste
  - [ ] Automatizar execução

- [ ] 5.2.2. Cenários de teste
  - [ ] Assinatura CAdES
  - [ ] Assinatura XAdES
  - [ ] Assinatura PAdES
  - [ ] Verificação de assinaturas
  - [ ] Timestamp
  - [ ] Cadeias de certificados

- [ ] 5.2.3. Testes com certificados reais
  - [ ] Certificados A1
  - [ ] Certificados A3
  - [ ] Diferentes ACs (Serpro, Receita, etc.)

### Fase 6: Validação e Testes de Compatibilidade

- [ ] 6.1. Compilação limpa
  - [ ] Build sem erros
  - [ ] Build sem warnings críticos
  - [ ] Validar todos os 13 módulos

- [ ] 6.2. Execução de testes
  - [ ] Todos os testes unitários passando
  - [ ] Todos os testes de integração passando
  - [ ] Cobertura de código adequada

- [ ] 6.3. Testes multi-versão Java
  - [ ] Compatibilidade com Java 11 (LTS anterior)
  - [ ] Compatibilidade com Java 17 (LTS atual)
  - [ ] Funcionalidade plena no Java 21 (LTS novo)

- [ ] 6.4. Testes de performance
  - [ ] Benchmarks de assinatura
  - [ ] Benchmarks de verificação
  - [ ] Comparação com versão Java 7

### Fase 7: Documentação

- [ ] 7.1. Atualizar README.md
  - [ ] Requisitos de Java 21
  - [ ] Instruções de build
  - [ ] Notas de migração

- [ ] 7.2. Atualizar documentação técnica
  - [ ] Changelog detalhado
  - [ ] Breaking changes
  - [ ] Guia de migração para usuários

- [ ] 7.3. Javadoc
  - [ ] Atualizar links para Java 21 docs
  - [ ] Corrigir warnings de javadoc
  - [ ] Gerar documentação atualizada

### Fase 8: Release e Entrega

- [ ] 8.1. Preparar release
  - [ ] Atualizar versão para 4.5.0 ou 5.0.0
  - [ ] Gerar artifacts
  - [ ] Assinar artefatos

- [ ] 8.2. Testes finais
  - [ ] Smoke tests
  - [ ] Validação em ambiente de homologação
  - [ ] Testes com Sinesp Assinador

- [ ] 8.3. Deploy
  - [ ] Publicar no Sonatype/Maven Central
  - [ ] Tag no GitHub
  - [ ] Release notes

---

## 🎯 Principais Desafios Identificados

### 1. Bug Crítico - getSubjectAlternativeNames() (Java 19+)
- **Prioridade**: ALTA
- **Impacto**: Falha na validação de certificados ICP-Brasil
- **Solução**: Ajustar CertificateExtra para aceitar listas de tamanhos variados
- **Severidade**: ⚠️ Média - Afeta validação, mas não impede compilação
- **Status**: Pendente

### 2. 🔥 Bug CRÍTICO - SunPKCS11 - Acesso a Tokens (Java 9+)
- **Prioridade**: CRÍTICA - BLOQUEADOR
- **Impacto**: **IMPOSSÍVEL usar certificados A3 (tokens/smartcards) no Java 9+**
- **Arquivos**: DriverKeyStoreLoader.java, PKCS11Logout.java
- **Problema**: APIs `sun.security.pkcs11.SunPKCS11` completamente removidas/alteradas no Java 9
- **Sintomas**:
  - `NoSuchMethodException` ao tentar instanciar SunPKCS11
  - `ClassNotFoundException` ou erros de reflexão
  - Impossível carregar drivers PKCS#11
- **Solução**: Refatoração completa para usar `Provider.configure()` API
- **Severidade**: 🔥🔥🔥 CRÍTICA - Funcionalidade principal quebrada
- **Esforço**: Alto - Requer refatoração significativa + testes extensivos
- **Status**: **NÃO IMPLEMENTADO - BLOQUEADOR PARA JAVA 9+**

### 3. Mudanças de API do Java
- **Removidos do JDK**: JAXB, JAX-WS (desde Java 11)
- **Status**: Dependências já explicitadas no core/pom.xml
- **Ação**: Validar versões e compatibilidade

### 4. Dependências Antigas
- **BouncyCastle 1.62**: Versão de 2017
- **Log4j 2.11.2**: Vulnerabilidades conhecidas (Log4Shell)
- **Ação**: Atualizar para versões recentes e seguras

### 5. Cobertura de Testes
- **Atual**: 19 testes apenas
- **Necessário**: Expandir significativamente
- **Crítico**: Criar testes antes de mudanças, especialmente para PKCS#11

---

## 📊 Módulos do Projeto

1. **bom** - Bill of Materials
2. **parent** - Parent POM
3. **core** - Core do Signer (⚠️ contém bug crítico)
4. **cryptography** - Operações criptográficas
5. **chain-icp-brasil** - Cadeia ICP-Brasil produção
6. **chain-icp-brasil-homolog** - Cadeia ICP-Brasil homologação
7. **chain-serpro-neosigner** - Cadeia Serpro
8. **chain-iti** - Cadeia ITI
9. **chain-iti-homolog** - Cadeia ITI homologação
10. **policy-engine** - Motor de políticas
11. **policy-impl-cades** - Implementação CAdES
12. **policy-impl-xades** - Implementação XAdES
13. **policy-impl-pades** - Implementação PAdES
14. **timestamp** - Carimbo de tempo
15. **signer-xmldsig** - Assinatura XML

---

## 🔗 Referências

- **Relato do Usuário**: docs-migracao-java21/relato-problema-usuario.md
- **Testador WS**: testador-ws/ (ferramenta em Go)
- **Java 21 Release Notes**: https://openjdk.org/projects/jdk/21/
- **Oracle JDK Migration Guide**: https://docs.oracle.com/en/java/javase/21/migrate/

---

## 📝 Notas Importantes

1. **Compatibilidade Reversa**: Avaliar se deve manter compatibilidade com Java 8/11 ou apenas 17+/21+
2. **Versão da Biblioteca**: Considerar bump de versão major (5.0.0) devido às mudanças significativas
3. **Comunidade**: Biblioteca é mantida pela comunidade, decisões devem ser documentadas
---

**Última Atualização**: 2026-01-23
**Versão do Código**: 4.5.0 (Released)
**Responsável pela Migração**: Em andamento
**Prazo Estimado**: 4-6 semanas

---

## 🔄 Changelog da Versão 4.5.0 (Análise)

### Commits Principais (desde versão anterior):
- **e79734ae** - Update documentation to version 4.5.0
- **0514bd63** - Adicionar Evandro Magalhães Leite Júnior à lista de desenvolvedores
- **60d28827** - feat: suporte a token DxToken no Linux e MacOs #431
- **24ec5278** - #432 correção para suportar a assinatura de hash com carimbo
- **948109ed** - Correção de erro ao assinar região do XML
- **b1eb9098** - chore: mudança relativa ao novo portal do Maven Central (Sonatype) #435

### Mudanças Relevantes para Migração:
- 📝 Documentação atualizada para 4.5.0
- 🔧 Suporte a DxToken adicionado em Configuration.java
- 🔧 Melhorias em assinatura XML
- 🔧 Configuração Maven Central atualizada
- ⚠️ **JAVA VERSION: PERMANECE 1.7**
- ⚠️ **BUGS CRÍTICOS: NÃO CORRIGIDOS**

### Impacto na Migração:
- ✅ Código está mais atualizado (4.5.0)
- ✅ Alguns bugs corrigidos
- ❌ **Migração para Java 21 AINDA NECESSÁRIA**
- ❌ **Bugs bloqueadores AINDA PRESENTES**
- ❌ **Plano de migração CONTINUA VÁLIDO** 