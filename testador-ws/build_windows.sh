#!/bin/bash

echo "Compiling for Windows..."

GOOS=windows GOARCH=amd64 go build -o testador-ws.exe .

if [ $? -eq 0 ]; then
    echo "Compilation successful!"
    echo "Output: testador-ws.exe"
else
    echo "Compilation failed."
fi
