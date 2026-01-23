#!/bin/bash

echo "Compilando para Mac ARM (darwin/arm64)..."
GOOS=darwin GOARCH=arm64 go build -o testador-ws-mac-arm .

if [ $? -eq 0 ]; then
    echo "Compilação para Mac ARM concluída com sucesso!"
    echo "Arquivo gerado: testador-ws-mac-arm"
else
    echo "Falha na compilação para Mac ARM."
fi
