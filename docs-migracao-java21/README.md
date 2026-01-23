# 📁 Documentação da Migração Java 7 → Java 21

Este diretório contém toda a documentação relacionada à migração do Demoiselle Signer de Java 7 para Java 21.

---

## 📚 Documentos Disponíveis

### 🎯 [RESUMO_EXECUTIVO.md](./RESUMO_EXECUTIVO.md) ⭐ **COMECE AQUI**
**Visão geral para gestores e stakeholders**
- Status atual do projeto
- Bugs críticos identificados
- Ordem de prioridades
- Riscos e decisões necessárias
- Métricas e estimativas

### 📋 [plano.md](./plano.md)
**Plano técnico completo de migração**
- 8 fases detalhadas
- Lista de tarefas (checkboxes)
- Módulos do projeto
- Desafios identificados
- Cronograma estimado

### 🔥 [BUG_CRITICO_PKCS11.md](./BUG_CRITICO_PKCS11.md) ⚠️ **BLOQUEADOR**
**Análise detalhada do bug de acesso a tokens**
- Problema: APIs SunPKCS11 removidas no Java 9+
- Impacto: Certificados A3 não funcionam
- Solução técnica detalhada
- Exemplos de código
- Plano de implementação

### ⏭️ [PROXIMOS_PASSOS.md](./PROXIMOS_PASSOS.md)
**Guia prático de execução**
- O que já foi feito
- Próximo passo crítico
- Comandos úteis
- Sequência de execução

### 📝 [relato-problema-usuario.md](./relato-problema-usuario.md)
**Contexto original do problema**
- Relato do usuário (Sinesp Assinador)
- Bug reportado por Ronald Carvalho
- Histórico da questão

---

## 🚀 Como Usar Esta Documentação

### Para Gestores/Decisores:
1. Leia primeiro: **RESUMO_EXECUTIVO.md**
2. Entenda os bloqueadores: **BUG_CRITICO_PKCS11.md**
3. Revise decisões necessárias no RESUMO_EXECUTIVO

### Para Desenvolvedores:
1. Leia: **RESUMO_EXECUTIVO.md** (visão geral)
2. Consulte: **plano.md** (tarefas detalhadas)
3. Foque em: **BUG_CRITICO_PKCS11.md** (prioridade máxima)
4. Execute: **PROXIMOS_PASSOS.md** (ações práticas)

### Para Analistas/QA:
1. Entenda o escopo: **plano.md** - Fase 5 e 6
2. Prepare testes: Verificar requisitos de testes de integração
3. Considere: Testes com tokens reais (SafeNet, Gemalto, etc.)

---

## ⚠️ ALERTAS IMPORTANTES

### 🔴 BLOQUEADOR CRÍTICO
**O código atual NÃO FUNCIONA com Java 9+** devido ao bug PKCS#11.

Certificados A3 (tokens/smartcards) são **INOPERANTES** sem a correção descrita em `BUG_CRITICO_PKCS11.md`.

### 🟡 Bug de Validação
Bug em `CertificateExtra.java` afeta certificados com extensões otherName no Java 19+.

---

## 📊 Status Atual

```
┌─────────────────────────────────────────────┐
│  MIGRAÇÃO JAVA 7 → JAVA 21                  │
│  Status: PLANEJAMENTO CONCLUÍDO             │
│  Data: 2026-01-23                           │
└─────────────────────────────────────────────┘

✅ Java 21 Instalado
✅ Análise Completa do Código
✅ Bugs Críticos Identificados
✅ Plano de Migração Criado

⚠️  Bloqueadores Identificados: 1
⚠️  Bugs de Alta Prioridade: 1

❌ Compilação com Java 21: FALHARÁ (PKCS#11)
❌ Certificados A3: NÃO FUNCIONARÃO

🎯 Próxima Ação: Corrigir bug PKCS#11
⏱️  Estimativa: 1-2 semanas
```

---

## 🎯 Prioridades

### P0 - CRÍTICA 🔥
- [ ] Corrigir bug PKCS#11 (DriverKeyStoreLoader.java, PKCS11Logout.java)

### P1 - ALTA ⚠️
- [ ] Corrigir bug CertificateExtra.java (getSubjectAlternativeNames)

### P2 - MÉDIA
- [ ] Atualizar POMs para Java 21
- [ ] Atualizar dependências (BouncyCastle, Log4j)

### P3 - NORMAL
- [ ] Expandir testes
- [ ] Documentação

---

## 📈 Progresso da Migração

```
Fase 1: Preparação e Análise        [████████████████████] 100% ✅
Fase 2: Correção de Bugs            [░░░░░░░░░░░░░░░░░░░░]   0% ⏳
Fase 3: Atualização de POMs         [░░░░░░░░░░░░░░░░░░░░]   0%
Fase 4: Atualização de Dependências [░░░░░░░░░░░░░░░░░░░░]   0%
Fase 5: Desenvolvimento de Testes   [░░░░░░░░░░░░░░░░░░░░]   0%
Fase 6: Validação Multi-versão      [░░░░░░░░░░░░░░░░░░░░]   0%
Fase 7: Documentação                [░░░░░░░░░░░░░░░░░░░░]   0%
Fase 8: Release                     [░░░░░░░░░░░░░░░░░░░░]   0%

Total: ████░░░░░░░░░░░░░░░░░░░░░░░░ 12.5%
```

---

## 🔗 Links Úteis

- **Repositório Oficial**: https://github.com/demoiselle/signer
- **Java 21 Release Notes**: https://openjdk.org/projects/jdk/21/
- **JDK Migration Guide**: https://docs.oracle.com/en/java/javase/21/migrate/
- **PKCS#11 Reference**: https://docs.oracle.com/en/java/javase/21/security/pkcs11-reference-guide1.html

---

## 📞 Contato

- **Comunidade Demoiselle**: Issues no GitHub
- **Ronald Carvalho (SERPRO)**: Contato técnico
- **Documentação Oficial**: https://www.frameworkdemoiselle.gov.br

---

**Última Atualização**: 2026-01-23  
**Versão da Documentação**: 1.0  
**Status**: 📝 Documentação completa - Aguardando início da implementação
