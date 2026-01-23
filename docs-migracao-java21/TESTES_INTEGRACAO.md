# Testes de Integração - Migração Java 21

## Status

⚠️ **PROBLEMA IDENTIFICADO**: Certificados auto-assinados requerem validação de CA

Os testes de integração em Java foram criados mas falharam devido a um requisito da biblioteca:
- Erro: "Não foi possível resgatar as CAs do certificado no provedor"
- Causa: Biblioteca valida cadeia de certificados e busca CAs automaticamente
- Certificado de teste é auto-assinado (sem CA)

## Soluções Possíveis

### Opção 1: Criar cadeia completa de certificados
```bash
# 1. Criar CA raiz
keytool -genkeypair -alias root-ca -keyalg RSA -keysize 2048 \
  -validity 3650 -keystore root-ca.jks -storepass changeit \
  -dname "CN=Test Root CA, O=Demoiselle Test, C=BR"

# 2. Exportar certificado da CA
keytool -exportcert -alias root-ca -keystore root-ca.jks \
  -storepass changeit -file root-ca.cer

# 3. Criar certificado final assinado pela CA
# (processo complexo, requer CSR)
```

### Opção 2: Usar testador-ws do projeto ⭐ **RECOMENDADO**

O projeto já possui um testador completo em Go:
- `testador-ws/` na raiz do projeto
- Cliente WebSocket para Assinador SERPRO
- 87 testes automatizados
- Compara respostas com arquivos golden
- Suporta testes negativos

## Testes de Integração Java

### Arquivos Criados

#### 1. `integration-tests/pom.xml`
POM independente para testes de integração:
```xml
<dependencies>
    <dependency>
        <groupId>br.gov.frameworkdemoiselle.component</groupId>
        <artifactId>demoiselle-signer-policy-impl-cades</artifactId>
        <version>4.5.0</version>
    </dependency>
    <dependency>
        <groupId>junit</groupId>
        <artifactId>junit</artifactId>
        <version>4.13.2</version>
        <scope>test</scope>
    </dependency>
</dependencies>
```

#### 2. `integration-tests/src/test/java/.../CAdESSignatureIntegrationTest.java`
Testes de assinatura CAdES:
- **Teste 1**: Assinatura CAdES Attached (conteúdo incluso)
- **Teste 2**: Assinatura CAdES Detached (apenas hash)
- **Teste 3**: Performance - Múltiplas assinaturas
- **Teste 4**: Diferentes tamanhos de arquivo
- **Teste 5**: Compatibilidade Java (verifica versão)

### Status dos Testes Java

❌ **BLOQUEADO** - Precisa certificados com CA válida ou workaround

```
[ERROR] Tests run: 5, Failures: 0, Errors: 4, Skipped: 0
[ERROR]   test01_CAdESAttachedSignature:77 » Signer Não foi possível resgatar as CAs
[ERROR]   test02_CAdESDetachedSignature:117 » Signer Não foi possível resgatar as CAs  
[ERROR]   test03_PerformanceMultipleSignatures:155 » Signer
[ERROR]   test04_DifferentFileSizes:198 » Signer Não foi possível resgatar as CAs
```

Único teste que passa:
✅ **test05_JavaVersionCompatibility** - Valida versão Java >= 11

## Testador WebSocket (testador-ws)

### Descrição

Cliente Go para testar Assinador SERPRO via WebSocket:
- Localização: `testador-ws/` na raiz
- Linguagem: Go 1.24.4
- Protocolo: WebSocket
- Testes: 87 cenários

### Executáveis Disponíveis

```bash
testador-ws/
├── testador-ws-assinador-serpro    # Linux
├── testador-ws.exe                  # Windows
├── testador-ws-mac-arm              # macOS ARM
```

### Como Usar

#### 1. Executar testes básicos
```bash
cd testador-ws
./testador-ws-assinador-serpro
```

#### 2. Atualizar arquivos golden
```bash
./testador-ws-assinador-serpro -update
```

#### 3. Testar com arquivo customizado
```bash
./testador-ws-assinador-serpro -t meu_teste.json
```

#### 4. Comparar com golden files
```bash
./testador-ws-assinador-serpro -test-golden
```

### Estrutura dos Testes

**Mensagem de teste** (`test_messages.json`):
```json
{
  "id": "1",
  "fileName": "test_sign.txt",
  "expectedToFail": false,
  "description": "Assinatura básica CAdES",
  "messageContent": {
    "command": "Sign",
    "inputData": "base64content",
    "type": "file"
  }
}
```

**Teste negativo** (deve falhar):
```json
{
  "id": "14",
  "fileName": "test_invalid.txt",
  "expectedToFail": true,
  "description": "Hash inválido (deve falhar)",
  "messageContent": {
    "command": "Sign",
    "inputData": "invalid_hash",
    "type": "hash"
  }
}
```

### Logs Gerados

1. **synthetic.log** - Resumo
```
Test 1: PASS
Test 2: FAIL - Expected error, got success
...
Total: 87, Passed: 82, Failed: 5
```

2. **detailed.log** - Detalhado
```
[2026-01-23 11:30:00] Sending: {"command":"Sign",...}
[2026-01-23 11:30:01] Received: {"status":"success",...}
[2026-01-23 11:30:01] Status: Success
```

## Comandos de Teste WebSocket

### Comandos Suportados

1. **Sign** - Assinatura simples
2. **BatchSign** - Assinatura em lote
3. **CoSign** - Co-assinatura
4. **BatchCoSign** - Co-assinatura em lote
5. **CounterSign** - Contra-assinatura
6. **Verify** - Verificação de assinatura
7. **GetInfo** - Informações do certificado

### Exemplo: Assinatura Detached

**Request**:
```json
{
  "command": "Sign",
  "inputData": "SGVsbG8gV29ybGQ=",
  "type": "file",
  "signatureType": "detached"
}
```

**Response**:
```json
{
  "status": "success",
  "signature": "MIIG...base64...",
  "signerCertificate": "MIIE...base64...",
  "signDate": "2026-01-23T14:30:00Z"
}
```

## Recomendação de Estratégia de Testes

### Fase Atual (Java 11)

1. ✅ **Testes Unitários** - 92% passando (12/13)
   - Core: PKCS11ProviderHelperTest
   - CAdES: PKCS1SignerTest, CAdESSignerTest, etc.

2. ⚠️ **Testes de Integração Java** - Bloqueados (CAs)
   - Arquivos criados mas não executáveis
   - Aguardando certificados válidos ou workaround

3. ✅ **Testador WebSocket** - Disponível
   - 87 testes end-to-end
   - Testa serviço real Assinador SERPRO

### Próximos Passos Recomendados

#### Opção A: Foco em Testes Unitários (rápido)
1. Expandir cobertura de testes unitários
2. Adicionar testes para BouncyCastle 1.78
3. Testar com Java 11, 17, 21

#### Opção B: Usar Testador WebSocket (completo)
1. Configurar ambiente de teste com Assinador SERPRO
2. Executar testador-ws contra serviço
3. Validar todos os 87 cenários

#### Opção C: Certificados Reais (ideal)
1. Obter certificado A3 ICP-Brasil de teste
2. Configurar token/smartcard
3. Executar testes de integração Java

## Configuração do Testador WebSocket

### Arquivo: `testador-ws/config/config.go`

```go
package config

const (
    ServerURL = "wss://assinador.serpro.gov.br/ws"
    TestTimeout = 1000  // segundos
    GoldenFilesDir = "golden_files"
    TestMessagesFile = "test_messages.json"
)
```

### Personalização

Para ambiente de desenvolvimento local:
```go
ServerURL = "ws://localhost:8080/assinador"
```

Para testes mais rápidos:
```go
TestTimeout = 30  // 30 segundos
```

## Métricas de Testes

### Testes Unitários (Java)
- **Total**: 13 testes
- **Passando**: 12 (92%)
- **Falhando**: 1 (network test - não relacionado à migração)
- **Tempo médio**: ~2-3 segundos

### Testes WebSocket (Go)
- **Total**: 87 cenários
- **Cobertura**:
  - Assinatura: 20 cenários
  - Co-assinatura: 15 cenários
  - Contra-assinatura: 10 cenários
  - Verificação: 12 cenários
  - Testes negativos: 30 cenários
- **Tempo médio**: ~60 segundos (depende do serviço)

## Troubleshooting

### Problema: "Não foi possível resgatar as CAs"

**Causa**: Certificado auto-assinado sem cadeia de confiança

**Soluções**:
1. Usar certificado real ICP-Brasil
2. Criar CA raiz + certificado intermediário
3. Mock da validação de CA (não recomendado)
4. Aguardar API que permita desabilitar validação

### Problema: Testador WebSocket não conecta

**Causa**: Serviço offline ou URL incorreta

**Soluções**:
```bash
# Verificar conectividade
curl -I https://assinador.serpro.gov.br

# Testar WebSocket manualmente
websocat wss://assinador.serpro.gov.br/ws
```

### Problema: Timeout nos testes

**Causa**: Rede lenta ou servidor sobrecarregado

**Soluções**:
```go
// Aumentar timeout em config/config.go
const TestTimeout = 3000  // 3000 segundos
```

## Referências

- **Plano de Migração**: `docs-migracao-java21/plano.md`
- **Fase 5 (Testes)**: `docs-migracao-java21/FASE_5_TESTES.md`
- **Testador WebSocket**: `testador-ws/README.md`
- **Testes CAdES**: `policy-impl-cades/src/test/java/`

## Conclusão

### Status Atual

✅ **Infraestrutura pronta**:
- Módulo integration-tests criado
- 5 testes de integração implementados
- Testador WebSocket disponível

⚠️ **Bloqueio técnico**:
- Testes Java bloqueados por validação de CA
- Precisam certificados reais ou workaround

### Próxima Ação Recomendada

**Usar testador-ws existente** para validação end-to-end enquanto:
1. Busca certificado ICP-Brasil de teste, OU
2. Implementa workaround para certificados auto-assinados, OU
3. Foca apenas em testes unitários (já 92% passando)

---

**Atualizado**: 2026-01-23  
**Autor**: Evandro Jr + GitHub Copilot  
**Fase**: 5/8 - Testes (parcialmente concluída)
