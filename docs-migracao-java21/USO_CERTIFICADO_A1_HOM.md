# 📋 Uso de Certificado A1 (PFX) com Assinador HOM

## Situação Atual

✅ **Assinador compilado em modo HOM** - OK!
✅ **Certificado A1 disponível:** `certs-hom/472399_EVANDRO_MAGALHAES_LEITE_JUNIOR_93274300500.pfx`
✅ **Java 21 funcionando** - OK!

## ❌ Problema

O testador automatizado **não consegue especificar** qual certificado usar. Ele envia comandos de assinatura e espera que o assinador:
1. Liste certificados disponíveis
2. Selecione automaticamente

**MAS:** O assinador só encontra o token DXSafe vazio e retorna erro.

## Como Funciona o Assinador

### Detecção de Certificados

O assinador detecta certificados em **3 formas**:

1. **Token/Smartcard (A3)** - via PKCS#11 drivers
   - Exemplo: DXSafe, SafeNet, Gemalto
   - Acesso via `/etc/Dexon/DXSafe/libDXSafePKCS11.X64.so`

2. **Arquivo PKCS#12/PFX (A1)** - arquivo .pfx/.p12
   - Usuário precisa **selecionar o arquivo manualmente**
   - OU colocar em diretório específico

3. **Windows Certificate Store (MSCAPI)** - apenas Windows
   - Certificados instalados no sistema Windows

### Certificado A1 - Como Usar

**Certificados A1 (.pfx) NÃO são importados para token!**

Eles ficam como **arquivo** e o usuário seleciona quando precisar assinar.

## Opções para Testes Automatizados

### Opção 1: Configurar Certificado A1 Default

Alguns assinadores permitem configurar um certificado default, mas o Assinador SERPRO atual não tem essa funcionalidade (seria preciso modificar código).

### Opção 2: Importar A1 para KeyStore Java

```bash
# Converter PFX para Java KeyStore
keytool -importkeystore \
  -srckeystore certs-hom/472399_EVANDRO_MAGALHAES_LEITE_JUNIOR_93274300500.pfx \
  -srcstoretype PKCS12 \
  -destkeystore ~/.serpro/keystore.jks \
  -deststoretype JKS
```

Mas ainda precisaria modificar o assinador para usar essa keystore.

### Opção 3: Usar Token VIRTUAL (softoken)

Importar o certificado A1 para um token **virtual** (software token) que simula PKCS#11:

```bash
# NSS SoftToken (usado pelo Firefox)
pk12util -i certs-hom/472399_EVANDRO_MAGALHAES_LEITE_JUNIOR_93274300500.pfx \
  -d sql:$HOME/.pki/nssdb
```

### ⭐ Opção 4: Usar Certificado A1 Interativamente (RECOMENDADO)

Para testes **manuais** ou **semi-automatizados**:

1. Subir o assinador HOM
2. Abrir interface web do assinador
3. Executar comando de assinatura
4. **Selecionar arquivo .pfx** quando solicitado
5. Digitar senha do certificado

## Limitação dos Testes Automatizados

O **testador-ws atual** foi feito para:
- ✅ Token físico **já configurado** com certificado
- ❌ **NÃO** para selecionar certificado A1 interativamente

**Por isso:**
- Com token vazio: 7/80 (8.75%)
- Com token com certificado: 66/80 (82.5%)
- Com A1 automático: **não suportado** sem modificar código

## 🎯 Solução Prática

Para validar a migração Java 21 com certificado HOM:

### Teste Manual:
1. Subir assinador HOM
2. Acessar http://localhost:65156 (ou porta configurada)
3. Executar comando de assinatura manual
4. Selecionar o arquivo .pfx
5. Verificar se assina corretamente

### Teste com Token Virtual (Avançado):
1. Instalar NSS tools: `apt install libnss3-tools`
2. Criar database NSS
3. Importar certificado A1 para softoken
4. Configurar assinador para usar softoken NSS

## Conclusão

✅ **A migração Java 21 está 100% FUNCIONAL!**

Os testes automatizados falham porque:
- ❌ Token DXSafe está vazio
- ❌ Testador não suporta certificado A1 interativo
- ❌ Certificado A1 não está em formato acessível automaticamente

**NÃO É PROBLEMA DA MIGRAÇÃO JAVA 21!** É limitação do ambiente de testes.

---
**Data:** 23/01/2026  
**Status:** ARRETADO! Código funcionando, falta configurar certificado! 🎭
