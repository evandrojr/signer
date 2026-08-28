# Bugfix Requirements Document

## Introduction

O método `prepareAlgAndLength()` em `CAdESSigner.java` sobrescreve incorretamente o campo `signPolicyHashAlg` do objeto `SignaturePolicy` com o OID do algoritmo de hash derivado do algoritmo de assinatura do certificado (ex: SHA-512 para SHA512withRSA). Esse campo representa o algoritmo usado para calcular o hash do **arquivo .der da política de assinatura**, e não o algoritmo de hash usado na assinatura do documento.

Como consequência, o atributo `SignaturePolicyIdentifier` (id-aa-ets-sigPolicyId) na assinatura CAdES é montado com o `hashAlgorithm` incorreto (SHA-512 em vez de SHA-256), causando rejeição pelo serviço VALIDAR do ITI conforme Nota Técnica Nº 4/2026/CGOPE/DITEC. O impacto atinge todas as assinaturas ICP-Brasil geradas pelo demoiselle-signer quando o algoritmo de assinatura difere do algoritmo de hash da política (ex: SHA512withRSA com política que usa SHA-256 para seu hash).

## Bug Analysis

### Current Behavior (Defect)

1.1 WHEN o certificado do assinante usa SHA512withRSA e a política de assinatura define SHA-256 como algoritmo de hash do arquivo .der da política THEN o sistema sobrescreve o campo `signPolicyHashAlg` da `SignaturePolicy` com o OID do SHA-512 (2.16.840.1.101.3.4.2.3) no método `prepareAlgAndLength()`

1.2 WHEN o atributo SignaturePolicyIdentifier é montado pelo `IdSigningPolicy.getValue()` após a execução de `prepareAlgAndLength()` THEN o sistema gera o campo `hashAlgorithm` do `sigPolicyHash` com OID SHA-512 em vez de SHA-256

1.3 WHEN o algoritmo de assinatura não é informado como parâmetro e o sistema seleciona um da lista da política (branch else do prepareAlgAndLength) THEN o sistema também sobrescreve o `signPolicyHashAlg` com o OID do hash do algoritmo selecionado

1.4 WHEN a assinatura CAdES gerada com hashAlgorithm incorreto é submetida ao serviço VALIDAR do ITI THEN a assinatura é reprovada por não conformidade com a política

### Expected Behavior (Correct)

2.1 WHEN o certificado do assinante usa qualquer algoritmo de assinatura (SHA512withRSA, SHA256withRSA, etc.) e a política de assinatura define um algoritmo de hash para o arquivo .der da política THEN o sistema SHALL preservar intacto o campo `signPolicyHashAlg` original carregado do arquivo .der da política, sem sobrescrevê-lo

2.2 WHEN o atributo SignaturePolicyIdentifier é montado pelo `IdSigningPolicy.getValue()` THEN o sistema SHALL usar o `signPolicyHashAlg` original da política (conforme definido no arquivo .der) para o campo `hashAlgorithm` do `sigPolicyHash`

2.3 WHEN o algoritmo de assinatura não é informado como parâmetro e o sistema seleciona um da lista da política THEN o sistema SHALL selecionar o algoritmo sem modificar o `signPolicyHashAlg` da política

2.4 WHEN a assinatura CAdES é gerada com o hashAlgorithm correto (igual ao definido na política) THEN o sistema SHALL produzir assinaturas válidas conforme a Nota Técnica Nº 4/2026/CGOPE/DITEC do ITI

### Unchanged Behavior (Regression Prevention)

3.1 WHEN o método `prepareAlgAndLength()` é executado com um algoritmo informado como parâmetro que consta na lista de algoritmos permitidos pela política THEN o sistema SHALL CONTINUE TO selecionar corretamente o `AlgAndLength` correspondente e configurar o algoritmo de assinatura no `pkcs1`

3.2 WHEN o método `prepareAlgAndLength()` é executado sem algoritmo informado como parâmetro THEN o sistema SHALL CONTINUE TO selecionar o segundo algoritmo da lista da política (índice 1) e configurar o `pkcs1` com esse algoritmo

3.3 WHEN o método `prepareAlgAndLength()` é executado com um algoritmo que não consta na lista de algoritmos permitidos pela política THEN o sistema SHALL CONTINUE TO lançar `SignerException` com mensagem "error.no.algorithm.policy"

3.4 WHEN o `algorithmConstraintSet` da política é nulo ou não define `signerAlgorithmConstraints` THEN o sistema SHALL CONTINUE TO usar o algoritmo configurado ou o DEFAULT como fallback

3.5 WHEN o atributo SignaturePolicyIdentifier é montado THEN o sistema SHALL CONTINUE TO incluir corretamente o `sigPolicyId` (OID da política), o `sigPolicyHash` (valor do hash) e o `sigPolicyQualifiers` (URI da política)
