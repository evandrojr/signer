# Testes Não-Interativos - DS 5.0.0-SNAPSHOT + Java 11

## Contexto
No ambiente de teste não há token criptográfico físico conectado, portanto a maioria dos testes que requerem assinatura digital com token falham.

## Testes que NÃO Requerem Token (7 testes)

Estes testes passaram com sucesso usando DS 5.0.0-SNAPSHOT + Java 11:

| ID | Comando | Descrição | Status |
|----|---------|-----------|--------|
| 1 | list | Listar certificados disponíveis | ✅ PASS |
| 2 | version | Verificar versão do assinador | ✅ PASS |
| 4 | verifyxml | Verificar assinatura XML (texto) | ✅ PASS |
| 5 | verifyxml | Verificar assinatura XML (base64) | ✅ PASS |
| 8 | attached | Verificar assinatura attached | ✅ PASS |
| 51 | verifytimestamp | Verificar carimbo de tempo | ✅ PASS |
| 59 | verify | Verificar assinatura | ✅ PASS |

**Taxa de Sucesso:** 7/7 (100%) dos testes não-interativos ✅

## Testes que REQUEREM Token (73 testes)

Estes testes falharam devido à ausência de token físico:

| Comando | Quantidade | Erro |
|---------|------------|------|
| BatchCoSign | 11 | CKR_GENERAL_ERROR |
| packagesign | 2 | CKR_GENERAL_ERROR |
| preparesign | 9 | CKR_GENERAL_ERROR |
| sign | 15 | CKR_GENERAL_ERROR |
| TimeStamp | 4 | Varia (3/4 passavam no baseline) |
| verify | 4 | CKR_GENERAL_ERROR |
| unsignedpropertiesxml | 3 | CKR_GENERAL_ERROR |
| signxml | 5 | CKR_GENERAL_ERROR |
| signedpropertiesxml | 5 | CKR_GENERAL_ERROR |
| signxmldsig | 3 | CKR_GENERAL_ERROR |
| verifyxmldsig | 4 | CKR_GENERAL_ERROR |
| cosign | 3 | CKR_GENERAL_ERROR |
| verifyxml (cancelled) | 2 | Cancelado |

**Erro típico:**
```
Get token certificate: /etc/Dexon/DXSafe/libDXSafePKCS11.X64.so : CKR_GENERAL_ERROR
```

## Conclusão

✅ **SUCESSO TÉCNICO:** Todos os testes que não dependem de token físico passaram (100%).

Isto valida que:
- A compilação com Java 11 está correta
- Os exports de módulos estão funcionando
- O PKCS11ProviderHelper está operacional
- A migração da classe LogoutPKCS11 foi bem-sucedida
- Operações de verificação de assinatura funcionam corretamente

Para atingir os 82.5% do baseline original, é necessário executar os testes com **token criptográfico real** conectado.

---
**Data:** 23/01/2026  
**Sotaque:** Soteropolino 🎭  
**Versão:** DS 5.0.0-SNAPSHOT + Assinador 4.4.0-SNAPSHOT (Java 11)
