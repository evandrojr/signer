# 🔥 BUG CRÍTICO: SunPKCS11 - Bloqueador para Java 9+

## Status: BLOQUEADOR PARA MIGRAÇÃO JAVA 21

**Data Identificação**: 2026-01-23
**Severidade**: 🔥🔥🔥 CRÍTICA
**Prioridade**: P0 - MÁXIMA

---

## Resumo Executivo

O código atual usa APIs internas do pacote `sun.security.pkcs11.SunPKCS11` que foram **completamente removidas/alteradas no Java 9**. Isso torna **IMPOSSÍVEL** usar certificados A3 (tokens USB, smartcards) em Java 9 ou superior.

**Impacto**: Sem correção, a biblioteca NÃO pode ser migrada para Java 21 mantendo funcionalidade de certificados A3.

---

## Problema Detalhado

### Arquivos Afetados

1. **DriverKeyStoreLoader.java** (3 locais problemáticos)
   - Linha 130: `Class.forName("sun.security.pkcs11.SunPKCS11").getConstructor(InputStream.class)`
   - Linha 135: `Class.forName("sun.security.pkcs11.SunPKCS11").getMethod("login", ...)`
   - Linha 170: `Class.forName("sun.security.pkcs11.SunPKCS11").getConstructor(String.class)`
   - Linha 248: `new sun.security.pkcs11.SunPKCS11(InputStream)`

2. **PKCS11Logout.java**
   - Linha 46: `import sun.security.pkcs11.SunPKCS11;`
   - Linha 56: `if (provider instanceof SunPKCS11)`
   - Linha 57: `((SunPKCS11) provider).logout();`

### APIs Removidas no Java 9+

#### ❌ Construtores Removidos:
```java
// Java 8 - FUNCIONA
new SunPKCS11(InputStream config)
new SunPKCS11(String configFile)

// Java 9+ - NÃO EXISTE MAIS
// NoSuchMethodException será lançada
```

#### ❌ Método login() Removido:
```java
// Java 8 - FUNCIONA
SunPKCS11.login(Subject, CallbackHandler)

// Java 9+ - NÃO EXISTE MAIS
// NoSuchMethodException será lançada
```

#### ❌ Método logout() Removido:
```java
// Java 8 - FUNCIONA
((SunPKCS11) provider).logout()

// Java 9+ - NÃO EXISTE MAIS
```

---

## Nova API (Java 9+)

### Mudança de Paradigma

No Java 9+, a configuração de PKCS#11 mudou para usar o método `Provider.configure()`:

```java
// ANTES (Java 8):
String config = "name=MyToken\nlibrary=/path/to/driver.so";
Provider p = new sun.security.pkcs11.SunPKCS11(
    new ByteArrayInputStream(config.getBytes())
);
Security.addProvider(p);

// DEPOIS (Java 9+):
// 1. Criar arquivo de configuração temporário
Path configFile = Files.createTempFile("pkcs11-", ".cfg");
Files.write(configFile, config.getBytes());

// 2. Obter provider template
Provider template = Security.getProvider("SunPKCS11");

// 3. Configurar provider
Provider p = template.configure(configFile.toString());

// 4. Adicionar ao Security
Security.addProvider(p);

// 5. Limpar arquivo temporário
Files.delete(configFile);
```

### Login no Java 9+

O método `login()` foi removido. No Java 9+, o login é gerenciado automaticamente:

```java
// Java 8:
pkcs11Provider.login(null, callbackHandler);

// Java 9+:
// Login é feito automaticamente ao acessar o KeyStore
// Usar KeyStore.CallbackHandlerProtection
KeyStore.Builder builder = KeyStore.Builder.newInstance(
    "PKCS11", 
    provider,
    new KeyStore.CallbackHandlerProtection(callbackHandler)
);
KeyStore ks = builder.getKeyStore();
```

### Logout no Java 9+

```java
// Java 8:
((SunPKCS11) provider).logout();

// Java 9+:
// Simplesmente remover o provider
Security.removeProvider(provider.getName());
```

---

## Solução Proposta

### Opção 1: Código Condicional por Versão Java (Recomendado)

Criar classe utilitária que detecta versão do Java e usa código apropriado:

```java
public class PKCS11ProviderHelper {
    
    private static final int JAVA_VERSION = getJavaVersion();
    
    public static Provider createProvider(String config) throws Exception {
        if (JAVA_VERSION >= 9) {
            return createProviderJava9Plus(config);
        } else {
            return createProviderJava8(config);
        }
    }
    
    private static Provider createProviderJava8(String config) throws Exception {
        // Código atual usando reflexão
        Constructor<?> ctor = Class.forName("sun.security.pkcs11.SunPKCS11")
            .getConstructor(InputStream.class);
        return (Provider) ctor.newInstance(
            new ByteArrayInputStream(config.getBytes())
        );
    }
    
    private static Provider createProviderJava9Plus(String config) throws Exception {
        // Novo código para Java 9+
        Path configFile = Files.createTempFile("pkcs11-", ".cfg");
        try {
            Files.write(configFile, config.getBytes());
            Provider template = Security.getProvider("SunPKCS11");
            return template.configure(configFile.toString());
        } finally {
            Files.deleteIfExists(configFile);
        }
    }
    
    private static int getJavaVersion() {
        String version = System.getProperty("java.version");
        if (version.startsWith("1.")) {
            return Integer.parseInt(version.substring(2, 3));
        } else {
            return Integer.parseInt(version.split("\\.")[0]);
        }
    }
}
```

### Opção 2: Apenas Java 9+ (Mais Simples)

Se decidir **NÃO manter compatibilidade com Java 8**, simplesmente remover todo o código de reflexão e usar apenas a nova API.

**Prós**:
- Código mais limpo e simples
- Sem reflexão
- Sem warnings de APIs internas

**Contras**:
- Perde compatibilidade com Java 8
- Usuários precisam migrar

---

## Plano de Implementação

### Fase 1: Preparação
- [ ] Criar branch `fix/pkcs11-java9-compatibility`
- [ ] Documentar comportamento atual com Java 8
- [ ] Configurar ambiente de testes com tokens reais

### Fase 2: Implementação
- [ ] Criar classe `PKCS11ProviderHelper` com lógica condicional
- [ ] Refatorar `DriverKeyStoreLoader.java`:
  - [ ] Substituir reflexão direta por `PKCS11ProviderHelper`
  - [ ] Atualizar `getKeyStoreFromDriver()`
  - [ ] Atualizar `getKeyStoreFromConfigFile()`
  - [ ] Atualizar `getKeyStore(String pinNumber)`
- [ ] Refatorar `PKCS11Logout.java`:
  - [ ] Implementar logout para Java 9+
  - [ ] Manter compatibilidade com Java 8

### Fase 3: Testes
- [ ] Testes unitários com mocks
- [ ] Testes com tokens reais:
  - [ ] SafeNet eToken
  - [ ] Gemalto/Thales
  - [ ] Watchdata
  - [ ] Outros fabricantes
- [ ] Validar em múltiplas versões:
  - [ ] Java 8
  - [ ] Java 11
  - [ ] Java 17
  - [ ] Java 21

### Fase 4: Validação
- [ ] Smoke tests em ambientes reais
- [ ] Testes com aplicações dependentes (Sinesp Assinador)
- [ ] Performance benchmarks

---

## Riscos e Mitigações

### Risco 1: Comportamento Diferente entre Versões
**Mitigação**: Testes extensivos em todas as versões suportadas

### Risco 2: Drivers PKCS#11 Incompatíveis
**Mitigação**: Testar com múltiplos fabricantes e versões de drivers

### Risco 3: Problemas de Permissões (Java Security Manager)
**Mitigação**: Documentar permissões necessárias, testar com SecurityManager ativo

### Risco 4: Tokens não Detectados
**Mitigação**: Logs detalhados, mensagens de erro claras para usuários

---

## Estimativa de Esforço

- **Análise e Planejamento**: 4 horas ✅ (concluído)
- **Implementação**: 16-24 horas
- **Testes**: 16-24 horas
- **Validação e Ajustes**: 8-16 horas
- **Total**: 44-68 horas (1-2 semanas)

---

## Referências

- [JDK-8168469: New API for PKCS#11 provider configuration](https://bugs.openjdk.org/browse/JDK-8168469)
- [JDK-8169329: SunPKCS11 provider constructor changes in JDK 9](https://bugs.openjdk.org/browse/JDK-8169329)
- [Java 9 Migration Guide - Security](https://docs.oracle.com/javase/9/migrate/toc.htm#JSMIG-GUID-7744EF96-5899-4FB2-B34E-86D49B2E89B6)
- [PKCS#11 Reference Guide](https://docs.oracle.com/en/java/javase/21/security/pkcs11-reference-guide1.html)

---

## Notas Importantes

⚠️ **ESTE BUG DEVE SER CORRIGIDO ANTES DE QUALQUER TENTATIVA DE BUILD COM JAVA 9+**

Sem esta correção:
- ❌ Certificados A3 não funcionarão
- ❌ Tokens USB não serão detectados
- ❌ SmartCards não poderão ser usados
- ❌ Principais casos de uso da biblioteca quebrados

**A migração para Java 21 está BLOQUEADA até este bug ser resolvido.**

---

**Última Atualização**: 2026-01-23
**Responsável**: A definir
**Status**: IDENTIFICADO - AGUARDANDO IMPLEMENTAÇÃO
