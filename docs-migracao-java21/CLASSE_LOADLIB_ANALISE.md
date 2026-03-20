# Análise da Classe LoadLib - Acesso Direto a sun.security.pkcs11.wrapper

## Problema Identificado

A classe `LoadLib.java` no Assinador SERPRO acessa **diretamente** as classes internas do Java:

```java
import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
import sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS;
import sun.security.pkcs11.wrapper.CK_TOKEN_INFO;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Constants;
import sun.security.pkcs11.wrapper.PKCS11Exception;
```

## Por Que LoadLib Precisa Desse Acesso?

A classe `LoadLib` implementa funcionalidades de **baixo nível** para:

1. **Descobrir dispositivos PKCS#11** conectados (tokens, smart cards)
2. **Ler informações do token** (label, modelo, serial)
3. **Listar certificados** disponíveis em cada slot
4. **Extrair dados** dos certificados (nome, CPF/CNPJ)

Essas operações requerem acesso direto à **biblioteca nativa PKCS#11** via JNI (Java Native Interface).

## Por Que Não Pode Usar PKCS11ProviderHelper?

O `PKCS11ProviderHelper` do Demoiselle Signer oferece apenas:
- `createProvider()` - Cria provider PKCS#11
- `logout()` - Faz logout do provider

**NÃO oferece:**
- ❌ Enumeração de slots
- ❌ Leitura de informações de token
- ❌ Busca de objetos em tokens
- ❌ Leitura de atributos de certificados

A classe `LoadLib` opera em um **nível mais baixo** que o Provider API do Java.

## Soluções Possíveis

### Opção 1: Manter Exports em Runtime (IMPLEMENTADA) ✅

**Vantagens:**
- ✅ Funciona imediatamente
- ✅ Não requer refatoração
- ✅ Mantém todas funcionalidades

**Desvantagens:**
- ⚠️ Depende de parâmetros JVM
- ⚠️ Pode quebrar em futuras versões do Java

**Implementação:**
```bash
java \
  --add-exports jdk.crypto.cryptoki/sun.security.pkcs11.wrapper=ALL-UNNAMED \
  --add-exports jdk.crypto.cryptoki/sun.security.pkcs11=ALL-UNNAMED \
  -jar serpro-signer.jar
```

### Opção 2: Usar Biblioteca Alternativa (NÃO IMPLEMENTADA)

Migrar para biblioteca PKCS#11 de terceiros:
- **iaik-pkcs11-wrapper** (IAIK)
- **pkcs11-wrapper** (Apache Commons)
- **jacknji11** (Joel Hockey)

**Vantagens:**
- ✅ Não depende de classes internas do Java
- ✅ Mais portável

**Desvantagens:**
- ❌ Requer refatoração completa da LoadLib
- ❌ Pode introduzir novos bugs
- ❌ Dependência externa adicional

### Opção 3: Usar JEP 403 (Java 21+)

Java 21 introduziu [JEP 403](https://openjdk.org/jeps/403) - Strongly Encapsulate JDK Internals

Eventualmente, `--add-exports` pode ser removido completamente.

**Solução futura:** Migrar para API pública quando disponível.

## Conclusão e Recomendação

✅ **MANTEMOS A OPÇÃO 1** (Exports em Runtime)

**Justificativa:**
1. LoadLib é crítica para funcionamento do assinador
2. Refatoração completa é arriscada
3. Exports funcionam perfeitamente no Java 11-21
4. Custo/benefício da migração é negativo

**Ação Obrigatória:**
- ✅ Scripts de inicialização DEVEM incluir `--add-exports`
- ✅ Documentação DEVE mencionar este requisito
- ✅ README DEVE ter seção sobre parâmetros JVM

## Scripts de Exemplo

### Linux/Mac
```bash
#!/bin/bash
java \
  --add-exports jdk.crypto.cryptoki/sun.security.pkcs11.wrapper=ALL-UNNAMED \
  --add-exports jdk.crypto.cryptoki/sun.security.pkcs11=ALL-UNNAMED \
  -jar serpro-signer.jar
```

### Windows
```bat
@echo off
java ^
  --add-exports jdk.crypto.cryptoki/sun.security.pkcs11.wrapper=ALL-UNNAMED ^
  --add-exports jdk.crypto.cryptoki/sun.security.pkcs11=ALL-UNNAMED ^
  -jar serpro-signer.jar
```

---
**Data:** 23/01/2026  
**Sotaque:** Soteropolino 🎭  
**Status:** LoadLib requer exports - solução documentada e implementada
