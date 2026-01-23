# Decisão: Target Java 11 (Compatibilidade LTS)

**Data:** 2026-01-23  
**Decisão por:** Evandro Jr + GitHub Copilot  
**Status:** ✅ Implementado

## Resumo

Decidimos compilar o projeto com **source=11** e **target=11** ao invés de **source=21** e **target=21**.

## Motivação

### Problema Identificado
Inicialmente compilamos com `target=21`, o que gerava bytecode classe 65 (Java 21).
**Isso significa que os JARs SÓ funcionariam em JVM 21+**, quebrando compatibilidade com Java 11 e 17.

### Opções Avaliadas

| Opção | Prós | Contras | Decisão |
|-------|------|---------|---------|
| **Target 21** | Simples, força migração | Quebra Java 11/17 | ❌ Rejeitado |
| **Target 11** | Compatível com LTS 11/17/21 | Não usa recursos Java 17+ | ✅ **ESCOLHIDO** |
| Multi-Release JAR | Máxima compatibilidade | Muito complexo | ❌ Rejeitado |
| Duas versões | Flexível | Manutenção duplicada | ❌ Rejeitado |

## Decisão Final

**Compilar com Java 11 target (source=11, target=11)**

### Justificativas

1. **Compatibilidade com todas LTS ativas:**
   - Java 11 (LTS, EOL: Set 2026)
   - Java 17 (LTS, EOL: Set 2029)
   - Java 21 (LTS, EOL: Set 2031)

2. **Java 8 está EOL desde 2019:**
   - Sem suporte público desde março/2019
   - Não faz sentido manter compatibilidade

3. **Código PKCS11ProviderHelper continua funcionando:**
   ```java
   // Detecta versão em RUNTIME, não em compile-time
   int version = getJavaVersion();
   if (version >= 9) {
       return createProviderJava9Plus(configPath);
   } else {
       return createProviderJava8(configStream);
   }
   ```

4. **Simplicidade vs Complexibilidade:**
   - Multi-Release JAR seria muito complexo
   - Target 11 é o melhor custo-benefício

5. **Alinhamento com ecosistema:**
   - A maioria dos projetos Java já migraram para Java 11+
   - Bibliotecas modernas exigem Java 11 mínimo

## Impacto Técnico

### O que PODE rodar os JARs compilados?
✅ Java 11  
✅ Java 17  
✅ Java 21  
✅ Qualquer JVM futura 11+

### O que NÃO PODE rodar?
❌ Java 8  
❌ Java 9  
❌ Java 10

### Recursos Disponíveis
Com `source=11`, podemos usar:
- ✅ `var` (Java 10)
- ✅ String.isBlank(), String.lines() (Java 11)
- ✅ Collection.toArray(IntFunction) (Java 11)
- ✅ Files.readString(), Files.writeString() (Java 11)
- ❌ Records (Java 14+)
- ❌ Pattern Matching (Java 17+)
- ❌ Virtual Threads (Java 21+)

## Validação

### Build Realizado
```bash
$ mvn clean compile
[INFO] BUILD SUCCESS
```

### Versão de Classe Gerada
- **Antes (target=21):** Classe versão 65 (Java 21)
- **Depois (target=11):** Classe versão 55 (Java 11)

### Arquivos Modificados
1. `pom.xml`:
   - `java.version`: 21 → 11
   - `maven.compiler.source`: 21 → 11
   - `maven.compiler.target`: 21 → 11

2. `bom/pom.xml`:
   - `java.version`: 21 → 11
   - `maven.compiler.source`: 21 → 11
   - `maven.compiler.target`: 21 → 11

## Comunicação aos Usuários

### Notas de Release (sugestão para v5.0.0)

**Requisitos Mínimos Atualizados:**
- ⚠️ **BREAKING CHANGE:** Java 11 ou superior agora é obrigatório
- ❌ Java 8 não é mais suportado
- ✅ Compatível com Java 11, 17, 21 e versões futuras

**Por quê Java 11?**
- Java 8 está sem suporte desde 2019
- APIs críticas do Java 9+ (PKCS#11) são necessárias
- Alinhamento com versões LTS modernas

**Como migrar:**
1. Atualize JVM para Java 11+ (recomendamos Java 21 LTS)
2. Atualize a biblioteca para 5.0.0
3. Teste com seus certificados/tokens

## Próximos Passos

- [x] Atualizar POMs para target=11
- [x] Validar compilação
- [x] Commit da mudança
- [ ] Executar testes (`mvn test`)
- [ ] Testar em JVM 11, 17 e 21
- [ ] Documentar em README.md
- [ ] Incluir em CHANGELOG.md

## Referências

- [JDK 11 Release Notes](https://openjdk.org/projects/jdk/11/)
- [Oracle Java SE Support Roadmap](https://www.oracle.com/java/technologies/java-se-support-roadmap.html)
- [Demoiselle Signer Issue Tracker](https://github.com/demoiselle/signer/issues)

---

**Decisão tomada em conjunto:**  
👨‍💻 Evandro Jr + 🤖 GitHub Copilot = 🎉 **Linda dupla!**
