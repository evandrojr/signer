# Análise de Dependências - Fase 4

**Data:** 2026-01-23  
**Status:** 🔄 Em andamento

---

## 📊 Dependências Atuais (versão 4.5.0)

### 🔴 CRÍTICO: Vulnerabilidades de Segurança

#### 1. **Log4j 2.11.2** - VULNERABILIDADE CRÍTICA
- **Versão Atual:** 2.11.2 (de 2019)
- **Vulnerabilidade:** CVE-2021-44228 (Log4Shell) - **CRITICAL**
- **CVSS Score:** 10.0 (máximo)
- **Impacto:** Remote Code Execution (RCE)
- **Descrição:** Permite execução remota de código através de JNDI lookup
- **Versão Recomendada:** 2.20.0+ (corrigido)
- **Prioridade:** 🔥 **URGENTE** - deve ser atualizado IMEDIATAMENTE

**Pacotes afetados:**
- `org.apache.logging.log4j:log4j-api:2.11.2`
- `org.apache.logging.log4j:log4j-core:2.11.2`
- `org.apache.logging.log4j:log4j-1.2-api:2.11.2`

#### 2. **JUnit 4.13.1** - Vulnerabilidade Conhecida
- **Versão Atual:** 4.13.1
- **Vulnerabilidade:** CVE-2020-15250 (baixa severidade)
- **Versão Corrigida:** 4.13.2
- **Prioridade:** ⚠️ Média (apenas em testes)

---

## 📦 Dependências a Atualizar

### 1. **BouncyCastle**

**Atual:**
```xml
<dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcmail-jdk15on</artifactId>
    <version>1.62</version>
</dependency>
```

**Análise:**
- **Versão Atual:** 1.62 (de 2017 - 7 anos atrás!)
- **Última Versão:** 1.78 (Jan 2024)
- **Compatibilidade:** `jdk15on` é para Java 1.5+
- **Java 11+:** Deve usar `jdk18on` (Java 1.8+)
- **Breaking Changes:** Possíveis, requer validação

**Proposta:**
```xml
<dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcmail-jdk18on</artifactId>
    <version>1.78</version>
</dependency>
```

**Atenção:** Mudar de `jdk15on` para `jdk18on` pode exigir ajustes no código!

---

### 2. **Log4j** 🔥

**Atual:**
```xml
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-api</artifactId>
    <version>2.11.2</version>
</dependency>
```

**Análise:**
- **Versão Atual:** 2.11.2 (Julho 2019)
- **Versão Segura Mínima:** 2.17.1 (Dez 2021)
- **Última Versão:** 2.23.0 (Jan 2024)
- **Recomendação:** 2.20.0 (LTS - Maio 2023)

**Proposta:**
```xml
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-api</artifactId>
    <version>2.20.0</version>
</dependency>
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.20.0</version>
</dependency>
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-1.2-api</artifactId>
    <version>2.20.0</version>
</dependency>
```

**Compatibilidade:** Log4j 2.20.0 requer Java 8+ (compatível com Java 11)

---

### 3. **SLF4J**

**Atual:**
```xml
<dependency>
    <groupId>org.slf4j</groupId>
    <artifactId>slf4j-log4j12</artifactId>
    <version>1.7.32</version>
</dependency>
```

**Análise:**
- **Versão Atual:** 1.7.32 (Set 2021)
- **Última Versão:** 2.0.11 (Jan 2024)
- **Problema:** `slf4j-log4j12` é para Log4j 1.x (deprecated)
- **Para Log4j 2.x:** Usar `log4j-slf4j-impl` ou `log4j-slf4j2-impl`

**Proposta:**
```xml
<!-- Remover slf4j-log4j12 -->
<!-- Adicionar (se necessário): -->
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-slf4j2-impl</artifactId>
    <version>2.20.0</version>
</dependency>
<dependency>
    <groupId>org.slf4j</groupId>
    <artifactId>slf4j-api</artifactId>
    <version>2.0.11</version>
</dependency>
```

---

### 4. **JUnit**

**Atual:**
```xml
<dependency>
    <groupId>junit</groupId>
    <artifactId>junit</artifactId>
    <version>4.13.1</version>
    <scope>test</scope>
</dependency>
```

**Análise:**
- **Versão Atual:** 4.13.1 (Out 2020)
- **Versão Segura:** 4.13.2 (Fev 2021)
- **JUnit 5 (Jupiter):** 5.10.1 (Dez 2023)

**Opção 1 - Atualização Simples (Recomendado):**
```xml
<dependency>
    <groupId>junit</groupId>
    <artifactId>junit</artifactId>
    <version>4.13.2</version>
    <scope>test</scope>
</dependency>
```

**Opção 2 - Migração para JUnit 5:**
```xml
<dependency>
    <groupId>org.junit.jupiter</groupId>
    <artifactId>junit-jupiter</artifactId>
    <version>5.10.1</version>
    <scope>test</scope>
</dependency>
<!-- Compatibilidade com JUnit 4 -->
<dependency>
    <groupId>org.junit.vintage</groupId>
    <artifactId>junit-vintage-engine</artifactId>
    <version>5.10.1</version>
    <scope>test</scope>
</dependency>
```

**Decisão:** Começar com 4.13.2 (menor impacto), migrar para 5.x depois.

---

### 5. **Commons IO**

**Atual:**
```xml
<dependency>
    <groupId>commons-io</groupId>
    <artifactId>commons-io</artifactId>
    <version>2.11.0</version>
</dependency>
```

**Análise:**
- **Versão Atual:** 2.11.0 (Jan 2022)
- **Última Versão:** 2.15.1 (Jan 2024)
- **Compatibilidade:** 100% backward compatible

**Proposta:**
```xml
<dependency>
    <groupId>commons-io</groupId>
    <artifactId>commons-io</artifactId>
    <version>2.15.1</version>
</dependency>
```

---

## 📋 Plano de Atualização

### Prioridade 1: Segurança 🔥
1. **Log4j:** 2.11.2 → 2.20.0 (URGENTE)
2. **JUnit:** 4.13.1 → 4.13.2 (Média)

### Prioridade 2: Compatibilidade Java 11+
3. **BouncyCastle:** 1.62 (jdk15on) → 1.78 (jdk18on)
4. **SLF4J:** Ajustar para Log4j 2.x

### Prioridade 3: Manutenção
5. **Commons IO:** 2.11.0 → 2.15.1

---

## ⚠️ Riscos e Mitigações

### Risco 1: BouncyCastle Breaking Changes
- **Risco:** Mudança de `jdk15on` para `jdk18on` pode quebrar APIs
- **Mitigação:** Rodar todos os testes após atualização
- **Plano B:** Reverter para versão 1.70 (jdk15on) se necessário

### Risco 2: Log4j API Changes
- **Risco:** Log4j 2.20.0 pode ter mudanças de API
- **Mitigação:** Versões 2.x são backward compatible
- **Validação:** Compilar e testar

### Risco 3: SLF4J Binding
- **Risco:** Mudar de slf4j-log4j12 para log4j-slf4j2-impl pode causar conflitos
- **Mitigação:** Remover binding antigo, adicionar novo
- **Validação:** Verificar logs funcionam

---

## 🧪 Estratégia de Validação

### Para cada atualização:

1. **Compilação:**
   ```bash
   mvn clean compile
   ```

2. **Testes Unitários:**
   ```bash
   mvn test
   ```

3. **Empacotamento:**
   ```bash
   mvn package
   ```

4. **Análise de Dependências:**
   ```bash
   mvn dependency:tree
   ```

5. **Verificação de Vulnerabilidades:**
   ```bash
   mvn org.owasp:dependency-check-maven:check
   ```

---

## 📝 Checklist de Execução

- [ ] 1. Atualizar Log4j (2.11.2 → 2.20.0)
  - [ ] log4j-api
  - [ ] log4j-core
  - [ ] log4j-1.2-api
  - [ ] Compilar e validar

- [ ] 2. Atualizar SLF4J
  - [ ] Remover slf4j-log4j12
  - [ ] Adicionar log4j-slf4j2-impl (se necessário)
  - [ ] Atualizar slf4j-api para 2.0.11
  - [ ] Compilar e validar

- [ ] 3. Atualizar JUnit (4.13.1 → 4.13.2)
  - [ ] Atualizar versão
  - [ ] Rodar testes

- [ ] 4. Atualizar BouncyCastle (1.62 jdk15on → 1.78 jdk18on)
  - [ ] Atualizar artifactId e version
  - [ ] Compilar
  - [ ] Rodar testes
  - [ ] Validar assinaturas funcionam

- [ ] 5. Atualizar Commons IO (2.11.0 → 2.15.1)
  - [ ] Atualizar versão
  - [ ] Compilar e validar

- [ ] 6. Validação Final
  - [ ] `mvn clean install`
  - [ ] Verificar todos os módulos
  - [ ] Rodar testes de integração
  - [ ] Verificar vulnerabilidades

---

## 📚 Referências

- [CVE-2021-44228 (Log4Shell)](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)
- [Log4j 2.x Security Vulnerabilities](https://logging.apache.org/log4j/2.x/security.html)
- [BouncyCastle Releases](https://www.bouncycastle.org/releasenotes.html)
- [JUnit 4.13.2 Release](https://github.com/junit-team/junit4/releases/tag/r4.13.2)
- [Apache Commons IO](https://commons.apache.org/proper/commons-io/)

---

**Próximo Passo:** Executar atualizações seguindo a ordem de prioridade.
