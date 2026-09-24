#!/bin/zsh
set -e

VERSION=4.6.3-SNAPSHOT
git checkout -b $VERSION 2>/dev/null || git checkout $VERSION

# Load SDKMAN if available
[[ -s "$HOME/.sdkman/bin/sdkman-init.sh" ]] && source "$HOME/.sdkman/bin/sdkman-init.sh"

sdk use java 25.0.4-tem 
sdk use maven 3.9.16
mvn versions:set -DnewVersion=$VERSION -DgenerateBackupPoms=false
mvn -pl bom versions:set-property -Dproperty=demoiselle.signer.version -DnewVersion='${project.version}' -DgenerateBackupPoms=false

# Mantém a etiqueta SCM (<scm><tag>) alinhada à versão do release em todos os pom.xml
TAG=${VERSION%-SNAPSHOT}
for pom in $(find . -name pom.xml -not -path '*/target/*'); do
    perl -pi -e "s#<tag>[^<]*</tag>#<tag>${TAG}</tag>#" "$pom"
done
mvn clean install
mvn test 

 
