# Documento de Requisitos: Suporte aos Novos Perfis de Certificados ICP-Brasil (Resolução 211)

## 1. Objetivo
Adaptar o **Demoiselle/Signer** e o **Assinador SERPRO** para suportar os novos perfis de certificados digitais da ICP-Brasil, conforme estabelecido pela Resolução 211. A implementação deve garantir compatibilidade com os certificados já existentes (perfil anterior) durante o período de transição, atualizando a lógica de extração e validação de dados, bem como corrigindo problemas de compatibilidade com versões mais recentes do Java.

## 2. Requisitos Funcionais (RF)

*   **RF01 - Suporte a Múltiplos Perfis (Retrocompatibilidade):** O sistema deve ser capaz de processar tanto certificados emitidos sob o perfil antigo quanto os emitidos sob o novo perfil da Resolução 211.
*   **RF02 - Identificação de Certificados por Política (OIDs):** O sistema deve identificar o tipo de certificado a partir do OID de política:
    *   **Pessoa Física (A3 e A4):** OIDs `2.16.76.1.2.3` e `2.16.76.1.2.4`.
    *   **Selo Eletrônico (SE-S e SE-H):** OIDs da família `2.16.76.1.2.201.n` (SE-S) e `2.16.76.1.2.202.n` (SE-H).
*   **RF03 - Extração do CPF via DN (Pessoa Física):** Para certificados de Pessoa Física, o sistema deve priorizar a extração do CPF a partir do campo `serialNumber` (OID `2.5.4.5`) localizado no *Distinguished Name* (DN).
*   **RF04 - Extração do CNPJ via DN (Selo Eletrônico):** Para certificados de Selo Eletrônico (Pessoa Jurídica), o sistema deve priorizar a extração do CNPJ a partir do campo `serialNumber` (OID `2.5.4.5`) localizado no *Distinguished Name* (DN).
*   **RF05 - Fallback de Extração (Período de Transição):** Caso o campo `serialNumber` no DN não contenha o CPF/CNPJ (ou seja um certificado do perfil antigo), o sistema deve utilizar os OIDs de *Subject Alternative Name* (SAN) como contingência (válido até 31/12/2028):
    *   CPF: OID `2.16.76.1.3.1` no SAN.
    *   CNPJ: OID `2.16.76.1.3.3` no SAN.
*   **RF06 - Extração do CNPJ da Autoridade de Registro (AR):** O sistema deve extrair o CNPJ da AR através da nova entrada no SAN com o OID `2.16.76.1.4.5.1`. Esta extração deve ocorrer **apenas** para certificados de Pessoa Física do novo perfil (conforme Demanda Interna 5341545).
*   **RF07 - Ignorar OIDs Extintos na Validação X509:** O sistema não deve exigir, e deve estar preparado para não encontrar, os seguintes OIDs extintos no SAN:
    *   `2.16.76.1.3.5` (Título de Eleitor)
    *   `2.16.76.1.3.9` (RIC)
    *   `2.16.76.1.3.11` (SIGEPE)
    *   `2.16.76.1.3.4` (Dados PF do responsável pelo certificado PJ)
    *   `2.16.76.1.3.2` (Nome do responsável pelo certificado PJ)
    *   `2.16.76.1.3.7` (CEI)
*   **RF08 - Remoção de Vinculação PF em PJ:** Para os novos certificados de Selo Eletrônico, o sistema não deve tentar extrair ou vincular dados de uma pessoa física (CPF/Nome) atrelada ao certificado.

## 3. Requisitos Não Funcionais (RNF)

*   **RNF01 - Compatibilidade de JDK:** A rotina de extração e processamento de dados do certificado (`X509`) **deve** funcionar corretamente em versões do Java superiores ao Java 8 (especificamente Java 11 e Java 17), corrigindo falhas existentes de reflection ou parse de extensões da Bouncy Castle/JCA.
*   **RNF02 - Desacoplamento de Formatações Legadas (Common Name):** A lógica do sistema não deve mais depender de convenções de *strings* da RFB no *Common Name* (CN) para extrair CPF ou CNPJ (ex: `Nome Civil:CPF` ou `Razão Social:CNPJ`). A extração deve ser estrita via `serialNumber` ou SAN.

## 4. Regras de Negócio (RN)

*   **RN01 - Novos Tipos de Certificado:** O sistema deve passar a reconhecer os novos tipos de certificados descritos na Resolução 211, extinguindo referências obrigatórias aos antigos nos novos fluxos:
    *   Selo Eletrônico em Software (SE-S)
    *   Selo Eletrônico em Hardware (SE-H)
    *   Aplicações Específicas em Software (AE-S)
    *   Aplicações Específicas em Hardware (AE-H)
*   **RN02 - Fim do SSL ICP-Brasil:** O sistema passa a tratar certificados para servidores/equipamentos (antigos SSL) apenas como "Aplicações Específicas" (AE-S e AE-H).
*   **RN03 - Classificação Estrita de Uso:**
    *   Certificados A3 e A4 determinam estritamente o uso por **Pessoa Física**.
    *   Certificados SE-S e SE-H determinam estritamente o uso por **Pessoa Jurídica** (Selo Eletrônico).
*   **RN04 - Fim dos Perfis Antigos:** Tipos A1, A2, S1, S2, S3 e S4 não existem no novo padrão e não devem ser atribuídos ou inferidos para os certificados emitidos a partir das novas regras.
