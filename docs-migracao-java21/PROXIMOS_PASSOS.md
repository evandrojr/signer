# Próximos Passos - Migração Java 21

## ✅ Concluído

1. **Java 21 Instalado**
   - OpenJDK 21.0.9 (Temurin) via sdkman
   - Configurado como versão padrão do sistema

2. **Plano de Migração Criado**
   - Análise completa do projeto realizada
   - Identificação de 13 módulos Maven
   - 348 arquivos Java mapeados
   - Bug crítico identificado e documentado

## 🎯 Próximo Passo Crítico

### PRIORIDADE 1: Corrigir Bug do getSubjectAlternativeNames()

**O quê fazer:**
```bash
# 1. Criar branch para a correção
git checkout -b fix/java21-subject-alternative-names

# 2. Executar testes atuais para estabelecer baseline
mvn clean test

# 3. Criar teste unitário que reproduz o problema
# Arquivo: core/src/test/java/org/demoiselle/signer/core/extension/CertificateExtraTest.java
```

**Problema:**
- Arquivo: `core/src/main/java/org/demoiselle/signer/core/extension/CertificateExtra.java`
- Linha 83: `if (list.size() != 2)` - Validação muito restritiva
- Java 19+: getSubjectAlternativeNames() pode retornar listas com 2, 3 ou 4 elementos para otherName

**Solução Sugerida:**
```java
// Linha 82-86 - ANTES:
for (List<?> list : certificate.getSubjectAlternativeNames()) {
    if (list.size() != 2) {
        logger.error(coreMessagesBundle.getString("error.extra.size.incorret"));
        throw new Exception(coreMessagesBundle.getString("error.extra.size.incorret"));
    }

// DEPOIS:
for (List<?> list : certificate.getSubjectAlternativeNames()) {
    if (list.size() < 2) {
        logger.warn("SubjectAlternativeName entry with unexpected size: " + list.size());
        continue; // Pula entradas mal formadas
    }
```

## 📋 Sequência de Execução Recomendada

### Semana 1: Correção do Bug e Setup Inicial
- [ ] Criar teste para reproduzir o bug
- [ ] Implementar correção
- [ ] Validar com certificados ICP-Brasil
- [ ] Atualizar POMs para Java 21

### Semana 2: Atualização de Dependências
- [ ] Atualizar BouncyCastle (1.62 → 1.70+)
- [ ] Atualizar Log4j (2.11.2 → 2.20.0+)
- [ ] Validar JAXB
- [ ] Compilar com Java 21

### Semana 3-4: Desenvolvimento de Testes
- [ ] Criar testes unitários para módulos críticos
- [ ] Configurar testes de integração com testador-ws
- [ ] Aumentar cobertura de testes

### Semana 5: Validação e Documentação
- [ ] Testes de regressão completos
- [ ] Testes de performance
- [ ] Atualizar documentação

### Semana 6: Release
- [ ] Build final
- [ ] Validação com Sinesp Assinador
- [ ] Deploy para Maven Central

## 🔧 Comandos Úteis

```bash
# Compilar com Java 21
source ~/.sdkman/bin/sdkman-init.sh
sdk use java 21.0.9-tem
mvn clean compile

# Executar todos os testes
mvn clean test

# Build completo
mvn clean install

# Gerar documentação Javadoc
mvn javadoc:aggregate -P aggregated

# Testar com testador-ws (após implementação)
cd testador-ws
go run testar.go
```

## 📞 Contatos e Referências

- **Ronald Carvalho (SERPRO)**: Mencionou versão 4.4.5-Snapshot e código alternativo
- **Versão Sugerida**: Testar 4.4.5-Snapshot primeiro
- **Repositório**: https://github.com/demoiselle/signer

## ⚠️ Avisos Importantes

1. **NÃO fazer push** direto para main sem testes completos
2. **SEMPRE criar branch** para cada fase da migração
3. **Documentar todas as mudanças** neste arquivo
4. **Executar testes** antes de cada commit
5. **Manter compatibilidade** com Java 17 se possível

---

**Data**: 2026-01-23
**Status**: Planejamento concluído - Pronto para execução
