#!/bin/bash
#
# Script de retry para deploy de SNAPSHOTs no Sonatype
# Uso: ./retry-deploy.sh [arguments...]
#   -release   modo release (ativa -P release para publicar no Maven Central)
#
set -e

JAVA_HOME=${JAVA_HOME:-$(dirname $(dirname $(readlink -f $(which java))))}
export JAVA_HOME
export PATH=$JAVA_HOME/bin:$PATH

cd "$(dirname "$0")"

PROFILE=""
if [ "$1" = "-release" ]; then
    PROFILE="-P release"
    echo "Modo RELEASE ativado"
fi

for i in {1..20}; do
    echo ""
    echo "=== Tentativa de deploy #$i ==="
    echo ""
    mvn clean deploy \
        -Dmaven.test.skip=true \
        -Dmaven.javadoc.skip=true \
        -B \
        $PROFILE \
        -Dgpg.passphrase="" \
        -Dgpg.arguments="--pinentry-mode loopback" \
        -Dmaven.wagon.http.retryHandler.count=5 \
        -Dmaven.wagon.http.connectionTimeout=600000 \
        -Dmaven.wagon.http.readTimeout=600000 \
        -Dorg.slf4j.simpleLogger.log.org.apache.maven.cli.transfer.Slf4jMavenTransferListener=warn
    
    if [ $? -eq 0 ]; then
        echo ""
        echo "=== Deploy bem-sucedido na tentativa #$i ==="
        exit 0
    fi
    
    echo ""
    echo "=== Falha na tentativa #$i. Retry em 15s... ==="
    sleep 15
done

echo ""
echo "=== Falha após 20 tentativas ==="
exit 1
