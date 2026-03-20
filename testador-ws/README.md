# Testador Assinador SERPRO

Este projeto é uma ferramenta para testar o serviço de assinatura digital Assinador SERPRO. Ele envia uma série de mensagens de teste predefinidas para o serviço websocket do SERPRO e compara as respostas com arquivos "golden" para garantir que o serviço esteja funcionando corretamente.

## Funcionalidades

- Envia uma variedade de mensagens de teste para o serviço Assinador SERPRO.
- Compara as respostas com arquivos "golden" para validar o comportamento do serviço.
- Gera logs sintéticos e detalhados para cada execução de teste.
- Pode atualizar os arquivos "golden" com novas respostas do serviço.
- Suporta testes que devem falhar intencionalmente (testes negativos).
- Contabiliza e exibe um resumo dos resultados dos testes (total, aprovados, falhas).
- Configuração centralizada no pacote `config` para fácil manutenção.

## Arquitetura

O projeto é organizado em pacotes modulares:

- **main**: Ponto de entrada da aplicação (`testar.go`)
- **config**: Configurações centralizadas (URLs, timeouts, caminhos)
- **requests**: Lógica de comunicação WebSocket e processamento de respostas

## Pré-requisitos

- Go 1.24.4 ou superior

## Configuração

As configurações do projeto estão centralizadas no arquivo `config/config.go`, incluindo:

- `ServerURL`: URL do serviço websocket do Assinador SERPRO
- `TestTimeout`: Timeout para as requisições (padrão: 1000 segundos)
- `GoldenFilesDir`: Diretório dos arquivos golden (padrão: "golden_files")
- `TestMessagesFile`: Arquivo padrão com as mensagens de teste (padrão: "test_messages.json")

Para modificar essas configurações, edite o arquivo `config/config.go`.

## Uso

Para executar os testes, use o seguinte comando:

```sh
go run testar.go
```

Isso enviará as mensagens de teste definidas em `test_messages.json` para o serviço Assinador SERPRO.

### Flags de Linha de Comando

-   `-update`: Atualiza os arquivos "golden" com as respostas mais recentes do serviço.
    ```sh
    go run testar.go -update
    ```
-   `-test-golden`: Compara as respostas do servidor com os arquivos "golden" existentes.
    ```sh
    go run testar.go -test-golden
    ```
-   `-t <caminho_do_arquivo>`: Especifica um arquivo JSON de mensagens de teste para usar em vez do padrão `test_messages.json`.
    ```sh
    go run testar.go -t meu_arquivo_de_testes.json
    ```

## Testes Negativos (Expected to Fail)

O testador suporta testes que devem falhar intencionalmente, úteis para validar tratamento de erros. Para marcar um teste como esperado falhar, adicione os campos `expectedToFail` e `description` no JSON:

```json
{
  "id": "14",
  "fileName": "test_ws_bachcosign.txt",
  "expectedToFail": true,
  "description": "Múltiplos hashes com apenas uma assinatura (deve falhar)",
  "messageContent": {
    "command": "BatchCoSign",
    "listOfInputData": ["hash1", "hash2"],
    "listOfInputSignatures": ["signature1"],
    "type": "hash"
  }
}
```

Quando um teste é marcado como `expectedToFail: true`:
- Se o servidor **retornar erro**: teste **passa** ✓ (comportamento esperado)
- Se o servidor **não retornar erro**: teste **falha** ✗ (deveria ter falhado)

O log mostrará: `Status: Success (Expected Failure: <description>)`

## Resultados dos Testes

Ao final da execução, um resumo dos resultados é exibido no console:

```
====================================================
Total de testes: 87
Testes passados: 82
Testes com falha: 5
====================================================
Testes concluídos. Logs detalhados salvos em 'detailed.log' e sintéticos em 'synthetic.log'.
```

## Estrutura do Projeto

- `testar.go`: O ponto de entrada principal da aplicação.
- `config/config.go`: Contém as constantes de configuração compartilhadas (URLs, timeouts, diretórios).
- `requests/requests.go`: Contém a lógica para enviar requisições ao serviço Assinador SERPRO e processar as respostas.
- `gerador-de-testes/generate_test_messages.go`: Um utilitário para gerar o arquivo `test_messages.json` a partir dos arquivos de teste no diretório `tests`.
- `test_messages.json`: Um arquivo JSON contendo as mensagens de teste a serem enviadas ao serviço.
- `golden_files/`: Um diretório contendo os arquivos "golden", que são as respostas esperadas do serviço.
- `gerador-de-testes/tests/`: Diretório contendo arquivos de teste individuais.
- `resources/`: Diretório contendo recursos necessários para os testes (ex: `simple.xml`).
- `synthetic.log`: Um arquivo de log contendo um resumo dos resultados dos testes.
- `detailed.log`: Um arquivo de log contendo informações detalhadas sobre cada requisição e resposta.

## Contribuindo

Pull requests são bem-vindos. Para alterações importantes, abra uma issue primeiro para discutir o que você gostaria de mudar.

Por favor, certifique-se de atualizar os testes conforme apropriado.