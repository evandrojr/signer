# Checklist de Implementação: Resolução 211 ICP-Brasil

Este checklist reflete os passos de desenvolvimento necessários para cumprir os requisitos definidos em `requisitos-resolucao-211.md`.

## Fase 1: Atualização de Infraestrutura e Dependências

- [ ] (RNF01) Garantir que o ambiente de build e teste esteja configurado para JDK 11/17+.
- [ ] (RNF01) Atualizar a biblioteca Bouncy Castle / componentes de criptografia JCA para versões compatíveis com os novos padrões e versões do Java (se necessário).
- [ ] (Geral) Atualizar a versão do projeto (ex: de 4.5.1 para 4.6.0) nos arquivos `pom.xml` (ou `build.gradle`), conforme versionamento semântico definido.

## Fase 2: Mapeamento de OIDs e Constantes

- [ ] (RF02, RN01) Cadastrar/mapear os OIDs de políticas para os novos tipos de certificados:
  - [ ] Pessoa Física (A3, A4): `2.16.76.1.2.3`, `2.16.76.1.2.4`.
  - [ ] Selo Eletrônico em Software (SE-S): `2.16.76.1.2.201.n`.
  - [ ] Selo Eletrônico em Hardware (SE-H): `2.16.76.1.2.202.n`.
- [ ] (RF06) Cadastrar/mapear o novo OID no SAN para CNPJ da Autoridade de Registro (AR): `2.16.76.1.4.5.1`.
- [ ] (RF07) Marcar como "não-obrigatórios" ou remover a validação estrita dos OIDs extintos no SAN:
  - [ ] Título de Eleitor (`2.16.76.1.3.5`).
  - [ ] RIC (`2.16.76.1.3.9`).
  - [ ] SIGEPE (`2.16.76.1.3.11`).
  - [ ] Dados PF do responsável pelo certificado PJ (`2.16.76.1.3.4`).
  - [ ] Nome do responsável pelo certificado PJ (`2.16.76.1.3.2`).
  - [ ] CEI (`2.16.76.1.3.7`).

## Fase 3: Lógica de Extração de Dados (Parsing)

- [ ] (RF03, RF05) Implementar a extração do CPF para Pessoa Física:
  - [ ] Tentar extrair do campo `serialNumber` (OID `2.5.4.5`) no DN.
  - [ ] Fallback: Se não encontrado no DN, extrair do OID `2.16.76.1.3.1` no SAN.
- [ ] (RF04, RF05) Implementar a extração do CNPJ para Selo Eletrônico (PJ):
  - [ ] Tentar extrair do campo `serialNumber` (OID `2.5.4.5`) no DN.
  - [ ] Fallback: Se não encontrado no DN, extrair do OID `2.16.76.1.3.3` no SAN.
- [ ] (RF06) Implementar a extração do CNPJ da AR (OID `2.16.76.1.4.5.1` no SAN) especificamente para certificados de Pessoa Física do novo perfil.
- [ ] (RF08, RN03) Modificar a lógica de modelos/entidades (ex: classe `ICPBRCertificate` ou similar) para suportar os novos tipos (Selo Eletrônico vs. Pessoa Jurídica tradicional) e garantir que a entidade de Selo Eletrônico não exija/valide dados do responsável PF.
- [ ] (RNF02) Remover rotinas de *fallback* que tentavam quebrar o campo *Common Name* (CN) usando *strings* como "Nome Civil:CPF" ou "Razão Social:CNPJ".

## Fase 4: Testes Automatizados

- [ ] Criar/obter massa de dados de teste (certificados de homologação) para o **Novo Perfil** (Pessoa Física e Selo Eletrônico com DN serialNumber).
- [ ] Manter e executar massa de dados de teste para o **Perfil Antigo** (Pessoa Física e Pessoa Jurídica com OIDs antigos no SAN).
- [ ] Escrever teste unitário para validar extração de CPF via DN e via SAN (Fallback).
- [ ] Escrever teste unitário para validar extração de CNPJ (Selo Eletrônico) via DN e via SAN (Fallback).
- [ ] Escrever teste unitário para verificar que não há erro de parsing ao omitir os OIDs extintos (Título Eleitoral, RIC, etc.).
- [ ] Validar compatibilidade dos testes em ambiente de integração contínua (CI) usando JDK 11 ou 17.
