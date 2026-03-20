# Diferença entre Sign Batch e BatchCoSign

## Resumo Rápido

| Comando | Uso | Entrada | Saída |
|---------|-----|---------|-------|
| **Sign** (único) | Assinar UM documento | 1 documento | 1 assinatura |
| **Sign** (batch) | Assinar VÁRIOS documentos | N documentos | N assinaturas (1 por doc) |
| **CoSign** | Co-assinar (adicionar assinatura) | 1 documento + 1 assinatura prévia | 1 assinatura (com 2 assinantes) |
| **BatchCoSign** | Co-assinar VÁRIOS documentos | N documentos + N assinaturas prévias | N assinaturas (cada uma com 2+ assinantes) |

## 1. Sign - Assinatura Simples

Assina um único documento.

**Exemplo:**
```json
{
  "command": "sign",
  "type": "text",
  "listOfInputData": ["Meu documento único"],
  "signaturePolicy": "RB",
  "algorithm": "SHA256withRSA"
}
```

**Resultado:** 1 assinatura com 1 assinante

---

## 2. Sign (Batch) - Assinatura em Lote

Assina **múltiplos documentos** com a **mesma chave privada** em uma única operação.

**Exemplo:**
```json
{
  "command": "sign",
  "type": "text",
  "listOfInputData": [
    "Documento A",
    "Documento B", 
    "Documento C"
  ],
  "signaturePolicy": "RB",
  "algorithm": "SHA256withRSA"
}
```

**Resultado:** 3 assinaturas independentes (1 para cada documento)

**Vantagem:** Solicita o PIN do certificado **apenas uma vez** para assinar todos os documentos.

**Campo importante:** `listOfInputData` - lista de documentos a assinar

---

## 3. CoSign - Co-Assinatura

Adiciona **uma segunda assinatura** a um documento **já assinado anteriormente**.

**Exemplo:**
```json
{
  "command": "sign",
  "type": "text",
  "inputData": "Documento já assinado",
  "signatureToCoSign": "MIAGCSqGSIb3DQEHAqCAMIACAQExDzANBglg...",
  "signaturePolicy": "RB",
  "algorithm": "SHA256withRSA"
}
```

**Resultado:** 1 assinatura contendo **2 assinantes** (original + novo)

**Uso típico:** Workflows de aprovação onde múltiplas pessoas precisam assinar o mesmo documento.

**Campo importante:** `signatureToCoSign` - a assinatura prévia em Base64

---

## 4. BatchCoSign - Co-Assinatura em Lote

Co-assina **múltiplos documentos já assinados** em uma única operação.

**Exemplo:**
```json
{
  "command": "BatchCoSign",
  "type": "text",
  "listOfInputData": [
    "Documento A já assinado",
    "Documento B já assinado"
  ],
  "listOfInputSignatures": [
    "MIAGCSqGSIb3DQEHAqCAMIACAQExDzANBglg...",
    "MIAGCSqGSIb3DQEHAqCAMIACAQExDzANBglg..."
  ],
  "signaturePolicy": "RB",
  "algorithm": "SHA256withRSA"
}
```

**Resultado:** 2 assinaturas, cada uma com **2+ assinantes**

**Importante:** O número de documentos em `listOfInputData` **deve ser igual** ao número de assinaturas em `listOfInputSignatures`.

**Campos importantes:**
- `listOfInputData` - lista de documentos já assinados
- `listOfInputSignatures` - lista de assinaturas prévias (1 para cada documento)

---

## Fluxo de Uso Típico

### Cenário 1: Assinatura de múltiplos contratos

```
1. Use: Sign (batch)
2. Entrada: ["Contrato_A.pdf", "Contrato_B.pdf", "Contrato_C.pdf"]
3. Saída: [assinatura_A, assinatura_B, assinatura_C]
```

### Cenário 2: Workflow de aprovação (múltiplos aprovadores)

```
1. Gestor 1 assina: Sign
   - Entrada: "Documento.pdf"
   - Saída: assinatura_1

2. Gestor 2 co-assina: CoSign
   - Entrada: "Documento.pdf" + assinatura_1
   - Saída: assinatura_2 (com 2 assinantes)

3. Diretor co-assina: CoSign
   - Entrada: "Documento.pdf" + assinatura_2
   - Saída: assinatura_3 (com 3 assinantes)
```

### Cenário 3: Múltiplos documentos com múltiplos aprovadores

```
1. Gestor 1 assina em lote: Sign (batch)
   - Entrada: ["Doc_A.pdf", "Doc_B.pdf"]
   - Saída: [assinatura_A1, assinatura_B1]

2. Gestor 2 co-assina em lote: BatchCoSign
   - Entrada: ["Doc_A.pdf", "Doc_B.pdf"] + [assinatura_A1, assinatura_B1]
   - Saída: [assinatura_A2, assinatura_B2] (ambas com 2 assinantes)
```

---

## Tipos Suportados

Todos os comandos suportam os seguintes tipos de entrada:

- **text** - Texto puro
- **hash** - Hash SHA-256 ou SHA-512 em Base64
- **base64** - Conteúdo binário em Base64
- **pdf** - Arquivo PDF em Base64 (apenas Sign)
- **file** - Seleção interativa de arquivo (apenas Sign único)

---

## Exemplo Completo: Arquivo de Teste

Veja o arquivo `exemplo-batch-sign-vs-cosign.json` para exemplos práticos de cada tipo de assinatura.

Para testar:
```bash
./testador-ws -t arquivos-de-teste/exemplo-batch-sign-vs-cosign.json
```
