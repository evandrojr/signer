# 🔧 Importando Certificado A1 para DXToken Físico

## Objetivo

Importar o certificado A1 (472399_EVANDRO_MAGALHAES_LEITE_JUNIOR_93274300500.pfx) para o **DXToken USB físico**.

## Status Atual do DXToken

- ✅ Hardware detectado: STMicroelectronics DXToken (Bus 003, Device 008)
- ✅ Driver instalado: `/etc/Dexon/DXSafe/libDXSafePKCS11.X64.so`
- ✅ Serviço DXSafe.service: RODANDO
- ❌ Token: VAZIO ou não inicializado (CKR_GENERAL_ERROR)

## Problema com pkcs11-tool

Tentativas de usar `pkcs11-tool` para inicializar/importar falham com:
```
error: PKCS11 function C_GetSlotList(NULL) failed: rv = CKR_GENERAL_ERROR (0x5)
Falha de segmentação
```

**Causa:** O token pode estar:
1. Não inicializado
2. Com firmware problemático
3. Bloqueado
4. Incompatível com a versão do driver

## Solução Alternativa: Usar Ferramentas da Dexon

O driver DXSafe pode ter ferramentas próprias de gerenciamento que não usam PKCS#11 padrão.

### Verificar ferramentas disponíveis:
```bash
dpkg -L dxsafe | grep bin
find /etc/Dexon -type f -executable
```

### Possíveis ferramentas:
- DXSafe Manager (interface gráfica)
- DXSafe CLI (linha de comando)
- Scripts de inicialização

## Próximos Passos

1. ✅ Procurar ferramentas de gerenciamento da Dexon
2. ⏭️ Inicializar o token com PIN
3. ⏭️ Importar certificado A1 pro token
4. ⏭️ Testar acesso via PKCS#11
5. ⏭️ Rodar testes de integração

---
**Status:** EM ANDAMENTO 🔧
**Data:** 23/01/2026 12:51
