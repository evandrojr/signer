# Novos perfis de certificado ICP-Brasil (Resolução 211) — orientações para quem usa o Demoiselle Signer

## 1. Contexto

A **Resolução nº 211 da ICP-Brasil** reformulou o leiaute dos certificados digitais emitidos pelas ACs da cadeia ICP-Brasil. Os "novos perfis" mudam **onde** os dados de identificação (CPF, CNPJ, nome do responsável, etc.) ficam gravados no certificado, e também introduzem novos tipos de certificado — como o **Selo Eletrônico (SE-S/SE-H)** e a **Aplicação Específica (AE-S/AE-H)**.

Durante o período de transição, convivem **dois formatos simultaneamente**: os certificados emitidos no perfil antigo (ainda na validade) e os emitidos no perfil novo. Logo, se o seu sistema lê dados do certificado, ele precisa continuar funcionando com os dois formatos **sem exigir que o usuário troque de certificado**.

O **Demoiselle Signer resolve esse problema de forma transparente**: você não precisa saber "se o certificado é do perfil antigo ou novo" — a biblioteca detecta o formato e expõe uma API única.

---

## 2. Perfil antigo vs. perfil novo — onde cada dado está

| Informação | Perfil antigo | Perfil novo (Resolução 211) |
|---|---|---|
| Nível/tipo do certificado (A1–A4, S1–S4) | Extensão `certificatePolicies` — OIDs `2.16.76.1.2.{1-4}` e `2.16.76.1.2.101-104` | Extensão `certificatePolicies` — mesmos OIDs acima + novos `SE-S/SE-H` (`201/202`) e `AE-S/AE-H` (`203/204`) |
| CPF (PF) | SAN `OtherName` `2.16.76.1.3.1` (`dados-pf`) | atributo `serialNumber` (`2.5.4.5`) do *Subject DN* |
| CNPJ (PJ) | SAN `OtherName` `2.16.76.1.3.3` (CNPJ) ou `2.16.76.1.3.7` (CEI) | atributo `serialNumber` (`2.5.4.5`) do *Subject DN* |
| CNPJ do responsável (PJ) / nome do responsável | SAN `OtherName` `2.16.76.1.3.2`, `2.16.76.1.3.4` | não obrigatório; campos de responsável retornam `null` |
| CNPJ da Autoridade de Registro (AR) | não previsto | Exclusivamente para certificados de governo o CNPJ da AR é encontrado na extensão SAN `OtherName` `2.16.76.1.4.5.1` |
| Dados de Equipamento | SAN `OtherName` `2.16.76.1.3.8` | mantido na SAN |

---

## 3. OIDs de tipo/nível mapeados pelo `BasicCertificate`

Constantes em `org.demoiselle.signer.core.extension.BasicCertificate`:

| Constante | OID | Nível retornado |
|---|---|---|
| `OID_A1_CERTIFICATE` | `2.16.76.1.2.1` | `A1` |
| `OID_A2_CERTIFICATE` | `2.16.76.1.2.2` | `A2` |
| `OID_A3_CERTIFICATE` | `2.16.76.1.2.3` | `A3` |
| `OID_A4_CERTIFICATE` | `2.16.76.1.2.4` | `A4` |
| `OID_S1_CERTIFICATE` … `OID_S4_CERTIFICATE` | `2.16.76.1.2.101-104` | `S1`–`S4` |
| `OID_SE_S_CERTIFICATE` *(novo)* | `2.16.76.1.2.201` | `SE-S` |
| `OID_SE_H_CERTIFICATE` *(novo)* | `2.16.76.1.2.202` | `SE-H` |
| `OID_AE_S_CERTIFICATE` *(novo)* | `2.16.76.1.2.203` | `AE-S` |
| `OID_AE_H_CERTIFICATE` *(novo)* | `2.16.76.1.2.204` | `AE-H` |

- `getCertificateType()` retorna `"A"`, `"S"`, `"SE"` ou `"AE"`.
- `isSeloEletronico()` → `true` para `SE-S`/`SE-H`; `isAplicacaoEspecifica()` → `true` para `AE-S`/`AE-H`.

---

## 4. Como buscar as informações no objeto do Demoiselle

Tudo passa por **`BasicCertificate`** (`org.demoiselle.signer.core.extension`). Você instancia a partir de bytes, `InputStream` ou `X509Certificate`.

```java
import org.demoiselle.signer.core.extension.BasicCertificate;
import org.demoiselle.signer.core.extension.ICPBRCertificatePF;
import org.demoiselle.signer.core.extension.ICPBRCertificatePJ;
import org.demoiselle.signer.core.extension.ICPBRCertificateSE;

// a partir do X509Certificate (ex.: já carregado do seu provider/módulo criptográfico)
X509Certificate x509 = ...;
BasicCertificate cert = new BasicCertificate(x509);

// a partir dos bytes da cadeia de certificação
// BasicCertificate cert = new BasicCertificate(certBytes);
```

Forma canônica para identificar perfil/tipo — **funciona igual para perfil antigo e novo**:

```java
String nivel = cert.getCertificateLevel();   // "A1".."A4", "S1".."S4", "SE-S", "SE-H", "AE-S", "AE-H" (null se sem policy)
String tipo  = cert.getCertificateType();    // "A", "S", "SE", "AE"
```

Forma canônica para identificar o titular:

```java
if (cert.hasCertificateSE()) {                       // SELO ELETRONICO (novo perfil)
    ICPBRCertificateSE se = cert.getICPBRCertificateSE();
    String cnpj   = se.getCNPJ();      // serialNumber (2.5.4.5)
    String cnpjAR = se.getCnpjAR();    // OID 2.16.76.1.4.5.1 (null se ausente)
} else if (cert.hasCertificatePF()) {
    ICPBRCertificatePF pf = cert.getICPBRCertificatePF();
    String cpf    = pf.getCPF();
    String cnpjAR = pf.getCnpjAR();
} else if (cert.hasCertificatePJ()) {
    ICPBRCertificatePJ pj = cert.getICPBRCertificatePJ();
    String cnpj   = pj.getCNPJ();
    String cnpjAR = pj.getCnpjAR();
}
```

Observações importantes da API:

- **`getCpf()`/`getCNPJ()` dão prioridade ao `serialNumber`** (perfil novo) e caem para a SAN `OtherName` (perfil antigo) quando ele não existe — você **não** precisa olhar para a SAN diretamente.
- **Selo Eletrônico no perfil novo** não tem CPF/nome de responsável: `getResponsibleName()`, `getBirthDate()`, etc. retornam `null` (comportamento seguro, sem exception).
- `getCertificateLevel()` e `getCertificateType()` podem retornar `null` se o certificado não tiver a extensão `certificatePolicies` e ele não for identificável — trate como tipo desconhecido.
- Para leitura direta da SAN (dados crus, perfil antigo), existe `CertificateExtra` (`isCertificatePF()`, `isCertificatePJ()`, `isCertificateEquipment()`, `isCertificateSE()`, `getOID_2_16_76_1_4_5_1().getCnpjAR()`, etc.). Prefira a API do `BasicCertificate/_ICPBR*` quando possível.
- **Equipamento/Aplicação** continua a ser detectado pela SAN: `hasCertificateEquipment()` e `getICPBRCertificateEquipment()`.

### Exemplo completo (leitura de arquivo PEM)

```java
BasicCertificate cert = new BasicCertificate(new FileInputStream("cert.pem"));

System.out.println("Nome      : " + cert.getName());
System.out.println("Nivel     : " + cert.getCertificateLevel());
System.out.println("Tipo      : " + cert.getCertificateType());
System.out.println("PF?       : " + cert.hasCertificatePF());
System.out.println("PJ?       : " + cert.hasCertificatePJ());
System.out.println("SE?       : " + cert.hasCertificateSE());
System.out.println("Equip.?   : " + cert.hasCertificateEquipment());
System.out.println("CNPJ AR   : " +
    (cert.getICPBRCertificateSE() != null ? cert.getICPBRCertificateSE().getCnpjAR()
     : cert.getICPBRCertificatePF() != null ? cert.getICPBRCertificatePF().getCnpjAR()
     : cert.getICPBRCertificatePJ() != null ? cert.getICPBRCertificatePJ().getCnpjAR()
     : null));
```

---

## 5. Versão mínima e declaração de dependência

| Item | Versão |
|---|---|
| Suporte inicial aos novos perfis (Resolução 211, Selo Eletrônico) | **4.6.0** (jun/2026) |
| **Versão recomendada** — última release publicada no Maven Central | **4.6.2** (set/2026) |


> A **4.6.2 é a versão mínima recomendada** para produção: além do suporte da 4.6.0, ela traz correções na detecção de Selo Eletrônico e de OIDs em `getCertificateLevel()`, além das cadeias ICP-Brasil v12 (compatíveis com a nova raiz).

Dependência Maven (a versão é a mesma em todos os módulos — use a do módulo que você consome):

```xml
<dependency>
    <groupId>org.demoiselle.signer</groupId>
    <artifactId>core</artifactId>   <!-- ou policy-impl-cades / policy-impl-xades / policy-impl-pades -->
    <version>4.6.2</version>
</dependency>
```

Se você usa as cadeias ICP-Brasil:

```xml
<dependency>
    <groupId>org.demoiselle.signer</groupId>
    <artifactId>chain-icp-brasil</artifactId>
    <version>4.6.2</version>
</dependency>
```

### Requisitos de runtime

- **Java 8+** (build oficial). Para apps em **Java 25+**, a 4.6.x já faz o parsing da SAN `OtherName` direto via BouncyCastle (sem depender de `sun.security.*`), então o novo perfil continua sendo lido normalmente.
- **BouncyCastle 1.80 (`jdk18on`)** — trazido como dependência transitiva pelo Signer; não precisa adicionar manualmente.
- A lib é **retrocompatível**: o código que hoje lê perfil antigo continua funcionando sem alteração; os novos métodos convivem com os antigos.

---

## 6. Recomendações para os devs

1. **Não faça parsing manual do certificado** (SAN/`serialNumber`/policy por conta própria). Use `BasicCertificate` — a lógica de "antigo vs. novo" já está encapsulada e coberta por testes.
2. **Migre de `CertificateExtra` para `BasicCertificate`/`ICPBRCertificate*`** quando quiser CPF/CNPJ, pois a versão nova já contempla o fallback do perfil novo (prioridade ao `serialNumber`).
3. **Prepare sua UI/regra de negócio para tratar Selo Eletrônico (SE)** e Aplicação Específica (AE) como tipos válidos — eles não são "PJ tradicional" e não têm responsável humano. Se o seu fluxo exige CPF de usuário, decida o tratamento (ex.: bloquear ou tratar à parte) em vez de deixar a leitura retornar valores inesperados.
4. **Teste com certificados reais dos dois perfis** (e do SE). Referências de testes no repositório:
   - `core/src/test/java/org/demoiselle/signer/core/extension/Resolution211Test.java`
   - `core/src/test/java/org/demoiselle/signer/core/extension/BasicCertificateTest.java`
   - `core/src/test/java/org/demoiselle/signer/core/extension/Resolution211CertificateDataTest.java`
5. **Não dependa de comportamento da SAN p/ SE.** Lembre-se: SE só é reconhecido pela *policy* (`SE-S`/`SE-H`), nunca pelos OIDs de SAN.
6. Ao **validar/emitir** assinaturas, garanta que a versão do `policy-engine`/`policy-impl-*` seja também **4.6.2** para manter paridade (as políticas de assinatura v2.4/v2.5 e a raiz v12 dependem disso).

---

## 7. Detalhes de implementação (referência rápida)

| Classe | Papel |
|---|---|
| `org.demoiselle.signer.core.extension.BasicCertificate` | API principal — nível, tipo, PF/PJ/SE/Equipamento, `getCnpjAR()` |
| `org.demoiselle.signer.core.extension.ICPBRSubjectAlternativeNames` | Orquestra a detecção (SAN + serialNumber + policy) |
| `org.demoiselle.signer.core.extension.CertificateExtra` | Acesso cru aos OIDs da SAN (perfil antigo, `getOID_2_16_76_1_4_5_1()`) |
| `org.demoiselle.signer.core.extension.ICPBRCertificatePF/PJ/SE` | DTOs tipados com `getCPF()/getCNPJ()/getCnpjAR()` |
| `org.demoiselle.signer.core.oid.OID_2_16_76_1_4_5_1` | OID `2.16.76.1.4.5.1` — CNPJ da AR (novo perfil e exclusivo para certificados de governo) |

