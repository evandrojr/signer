# ⚠️ REGRAS DE GIT - IMPORTANTE

## 🔴 REGRA CRÍTICA: Remotes

### ❌ NUNCA fazer push no remote `community`
### ✅ SEMPRE fazer push APENAS no remote `origin`

---

## Remotes Configurados

```bash
$ git remote -v
community	https://github.com/demoiselle/signer.git (fetch)
community	https://github.com/demoiselle/signer.git (push)
origin	https://github.com/evandrojr/signer.git (fetch)
origin	https://github.com/evandrojr/signer.git (push)
```

### Explicação:
- **`community`**: Repositório oficial Demoiselle (somente leitura para nós)
- **`origin`**: Fork pessoal do Evandro Jr (onde fazemos push)

---

## ✅ Comandos Permitidos

### Push (APENAS origin):
```bash
git push origin java21
git push origin main
git push origin --tags
```

### Fetch (ambos permitidos):
```bash
git fetch origin
git fetch community
```

### Pull (preferir origin):
```bash
git pull origin java21
```

---

## ❌ Comandos PROIBIDOS

### NUNCA executar:
```bash
# ❌ NÃO FAZER ISSO!
git push community java21
git push community main
git push community --tags
git push community --all
```

---

## 🔄 Workflow Correto

### 1. Trabalhar no branch local:
```bash
git checkout java21
# fazer mudanças
git add .
git commit -m "feat: alguma coisa"
```

### 2. Push APENAS para origin:
```bash
git push origin java21
```

### 3. Atualizar do upstream (community):
```bash
git fetch community
git merge community/main
# ou
git rebase community/main
```

### 4. Sincronizar origin:
```bash
git push origin java21
```

---

## 🛡️ Proteção

### Configurar push padrão (recomendado):
```bash
# Definir origin como remote padrão para push
git config --local remote.pushDefault origin
```

### Verificar configuração:
```bash
git config --local --get remote.pushDefault
# Deve retornar: origin
```

---

## 📋 Checklist Antes de Cada Push

Antes de executar `git push`, SEMPRE verificar:

- [ ] ✅ Estou pushando para `origin`?
- [ ] ❌ NÃO estou pushando para `community`?
- [ ] ✅ Branch correto?
- [ ] ✅ Commits revisados?

### Comando seguro:
```bash
# Sempre especificar o remote explicitamente
git push origin <branch>
```

---

## 🚨 O que fazer se pushar acidentalmente para community?

Se acidentalmente fizer push para `community`:

1. **Contactar mantenedores do projeto Demoiselle imediatamente**
2. **Solicitar remoção dos commits**
3. **Documentar o incidente**

**⚠️ Isso pode causar problemas no projeto oficial!**

---

## 📖 Resumo

| Ação | `origin` | `community` |
|------|----------|-------------|
| **Push** | ✅ **SIM** | ❌ **NUNCA** |
| **Fetch** | ✅ Sim | ✅ Sim |
| **Pull** | ✅ Sim | ⚠️ Evitar |

---

## 🎯 Regra de Ouro

**SEMPRE usar:**
```bash
git push origin <branch>
```

**NUNCA usar:**
```bash
git push community <qualquer-coisa>
```

---

**Data da Documentação:** 2026-01-23  
**Criado por:** Evandro Jr + GitHub Copilot  
**Motivo:** Evitar push acidental no repositório oficial Demoiselle
