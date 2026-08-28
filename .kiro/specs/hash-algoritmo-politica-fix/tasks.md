# Implementation Plan

- [x] 1. Write bug condition exploration test
  - **Property 1: Bug Condition** - signPolicyHashAlg sobrescrito após prepareAlgAndLength
  - **CRITICAL**: This test MUST FAIL on unfixed code - failure confirms the bug exists
  - **DO NOT attempt to fix the test or the code when it fails**
  - **NOTE**: This test encodes the expected behavior - it will validate the fix when it passes after implementation
  - **GOAL**: Surface counterexamples that demonstrate the bug exists
  - **Scoped PBT Approach**: Scope the property to concrete failing cases: SHA512withRSA com política SHA-256 (branch if) e seleção automática da lista (branch else)
  - Criar classe de teste em `policy-impl-cades/src/test/java/org/demoiselle/signer/policy/impl/cades/pkcs7/impl/CAdESSignerPrepareAlgBugConditionTest.java`
  - Configurar `SignaturePolicy` com `signPolicyHashAlg` = SHA-256 (OID: 2.16.840.1.101.3.4.2.1)
  - Configurar lista de `AlgAndLength` com algoritmos SHA512withRSA e SHA256withRSA
  - **Caso 1 (branch if)**: Configurar `pkcs1.algorithm` = "SHA512withRSA", executar `prepareAlgAndLength()`, assertar que `signPolicyHashAlg.algorithm.value` == "2.16.840.1.101.3.4.2.1" (SHA-256 original)
  - **Caso 2 (branch else)**: Não informar algoritmo, executar `prepareAlgAndLength()`, assertar que `signPolicyHashAlg.algorithm.value` == "2.16.840.1.101.3.4.2.1" (SHA-256 original)
  - **Caso 3 (branch if, ECDSA)**: Configurar `pkcs1.algorithm` = "SHA512withECDSA", assertar preservação de `signPolicyHashAlg`
  - Run test on UNFIXED code - expect FAILURE (this confirms the bug exists)
  - **EXPECTED OUTCOME**: Test FAILS — `signPolicyHashAlg` é sobrescrito de SHA-256 para SHA-512, confirmando o bug
  - Document counterexamples: `signPolicyHashAlg.algorithm.value` muda de "2.16.840.1.101.3.4.2.1" para "2.16.840.1.101.3.4.2.3"
  - Mark task complete when test is written, run, and failure is documented
  - _Requirements: 1.1, 1.2, 1.3_

- [x] 2. Write preservation property tests (BEFORE implementing fix)
  - **Property 2: Preservation** - Seleção de algoritmo e configuração do pkcs1
  - **IMPORTANT**: Follow observation-first methodology
  - Criar classe de teste em `policy-impl-cades/src/test/java/org/demoiselle/signer/policy/impl/cades/pkcs7/impl/CAdESSignerPrepareAlgPreservationTest.java`
  - **Observar no código não-corrigido:**
  - Observe: `prepareAlgAndLength()` com algoritmo "SHA512withRSA" na lista retorna `AlgAndLength` com OID correspondente ao SHA512withRSA
  - Observe: `prepareAlgAndLength()` sem algoritmo informado seleciona `listOfAlgAndLength.get(1)` e configura `pkcs1.algorithm` com o nome correspondente
  - Observe: `prepareAlgAndLength()` com algoritmo não reconhecido pelo `SignerAlgorithmEnum` lança `SignerException`
  - Observe: `prepareAlgAndLength()` com `algorithmConstraintSet` nulo retorna fallback com algoritmo configurado/DEFAULT
  - **Escrever testes property-based:**
  - Test 1: Para qualquer algoritmo informado que esteja na lista da política, o `AlgAndLength` retornado deve ter o mesmo `algID` e `minKeyLength`
  - Test 2: No branch else, `pkcs1.algorithm` deve ser configurado com o nome do algoritmo correspondente ao segundo item da lista
  - Test 3: Algoritmo não permitido pela política lança `SignerException` com mensagem "error.no.algorithm.policy"
  - Test 4: `algorithmConstraintSet` nulo retorna `AlgAndLength` com algoritmo configurado ou DEFAULT e `minKeyLength` = 0
  - Verify tests pass on UNFIXED code (comportamento de seleção/retorno não é afetado pelo bug)
  - **EXPECTED OUTCOME**: Tests PASS — confirma baseline de comportamento a preservar
  - Mark task complete when tests are written, run, and passing on unfixed code
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

- [x] 3. Correção da sobrescrita de signPolicyHashAlg em prepareAlgAndLength()

  - [x] 3.1 Implementar a correção
    - Arquivo: `policy-impl-cades/src/main/java/org/demoiselle/signer/policy/impl/cades/pkcs7/impl/CAdESSigner.java`
    - Método: `prepareAlgAndLength()` (linha ~1001)
    - **Branch if (algoritmo informado como parâmetro)**: Remover as 5 linhas que sobrescrevem `signPolicyHashAlg` (linhas ~1042-1046):
      ```java
      // REMOVER:
      String varOIDAlgorithmHash = varSignerAlgorithmEnum.getOIDAlgorithmHash();
      ObjectIdentifier varObjectIdentifier = signaturePolicy.getSignPolicyHashAlg().getAlgorithm();
      varObjectIdentifier.setValue(varOIDAlgorithmHash);
      AlgorithmIdentifier varAlgorithmIdentifier = signaturePolicy.getSignPolicyHashAlg();
      varAlgorithmIdentifier.setAlgorithm(varObjectIdentifier);
      signaturePolicy.setSignPolicyHashAlg(varAlgorithmIdentifier);
      ```
    - **Branch else (sem algoritmo informado)**: Remover as mesmas 5 linhas duplicadas (linhas ~1055-1060)
    - Manter a validação `if (varSignerAlgorithmEnum == null)` em ambos os branches
    - Manter a declaração de `varSignerAlgorithmEnum` para a validação null-check
    - Nenhuma alteração em `IdSigningPolicy.java`
    - _Bug_Condition: isBugCondition(input) onde sigAlgHashOID != policyHashOID AND algorithmConstraintSet IS NOT NULL_
    - _Expected_Behavior: signPolicyHashAlg.algorithm.value permanece inalterado após prepareAlgAndLength()_
    - _Preservation: Seleção de AlgAndLength, configuração de pkcs1, exceções e fallback permanecem idênticos_
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 3.1, 3.2, 3.3, 3.4_

  - [x] 3.2 Verificar que o teste de bug condition agora passa
    - **Property 1: Expected Behavior** - signPolicyHashAlg preservado após prepareAlgAndLength
    - **IMPORTANT**: Re-run the SAME test from task 1 - do NOT write a new test
    - O teste da task 1 codifica o comportamento esperado (signPolicyHashAlg inalterado)
    - Quando este teste passar, confirma que o comportamento esperado é satisfeito
    - Executar: `cd policy-impl-cades && mvn test -Dtest=CAdESSignerPrepareAlgBugConditionTest`
    - **EXPECTED OUTCOME**: Test PASSES (confirms bug is fixed)
    - _Requirements: 2.1, 2.2, 2.3_

  - [x] 3.3 Verificar que os testes de preservação continuam passando
    - **Property 2: Preservation** - Seleção de algoritmo e configuração do pkcs1
    - **IMPORTANT**: Re-run the SAME tests from task 2 - do NOT write new tests
    - Executar: `cd policy-impl-cades && mvn test -Dtest=CAdESSignerPrepareAlgPreservationTest`
    - **EXPECTED OUTCOME**: Tests PASS (confirms no regressions)
    - Confirmar que todos os testes ainda passam após a correção (sem regressões)

- [ ] 4. Checkpoint - Ensure all tests pass
  - Executar suite completa: `cd policy-impl-cades && mvn clean test`
  - Verificar que todos os testes unitários existentes continuam passando
  - Verificar que os novos testes (bug condition + preservation) passam
  - Ensure all tests pass, ask the user if questions arise.
