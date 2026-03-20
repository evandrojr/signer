# ⚠️ Problema: Seleção Manual de Certificados

## Situação

O testador automatizado está falhando porque o assinador **pede seleção manual** entre:
1. **SERPRO ID** - Keystores locais em `~/.serpro/serpro_signer_*.p12`
2. **NSS SoftToken** - Token virtual com certificado A1 importado

## Por que acontece?

O Demoiselle Signer detecta **múltiplas fontes** de certificados:
- FileSystemKeyStoreLoader: Arquivos .p12/.pfx locais (SERPRO ID)
- DriverKeyStoreLoader: PKCS#11 drivers (NSS SoftToken)

**O assinador espera que o USUÁRIO escolha** qual usar.

## Tentativas que NÃO funcionaram

❌ **Desabilitar SERPRO ID**: Assinador precisa dele para SSL  
❌ **Múltiplos certificados no NSS**: Ainda pede escolha  

## Opções para Resolver

### Opção 1: Modificar código do Assinador (INVASIVO)
Alterar a lógica de seleção para priorizar NSS automaticamente.

### Opção 2: Usar variável de ambiente (SE EXISTIR)
Verificar se o Demoiselle Signer aceita configuração para keystore default.

### Opção 3: IMPORTAR PARA DXTOKEN FÍSICO (RECOMENDADO!)
Como você pediu: importar o certificado A1 pro DXToken físico.
Assim teremos:
- ✅ Token físico funcional  
- ✅ Testes reais com hardware
- ✅ Validação completa da migração

## Decisão

Seguir com **Opção 3**: Importar certificado A1 pro **DXToken físico**!

---
**Próximo passo:** Importar 472399_EVANDRO_MAGALHAES_LEITE_JUNIOR_93274300500.pfx para DXToken
