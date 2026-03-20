#!/bin/bash

echo "Compiling for Linux..."

GOOS=linux GOARCH=amd64 go build -o testador-ws .

if [ $? -eq 0 ]; then
    echo "Compilation successful!"
    echo "Output: testador-ws"
else
    echo "Compilation failed."
fi
