#!/bin/zsh
set -e

VERSION=4.6.2-SNAPSHOT
git checkout -b $VERSION 2>/dev/null || git checkout $VERSION

# Load SDKMAN if available
[[ -s "$HOME/.sdkman/bin/sdkman-init.sh" ]] && source "$HOME/.sdkman/bin/sdkman-init.sh"

sdk use java 25.0.3-tem 
sdk use maven 3.9.16
mvn versions:set -DnewVersion=$VERSION -DgenerateBackupPoms=false
mvn -pl bom versions:set-property -Dproperty=demoiselle.signer.version -DnewVersion='${project.version}' -DgenerateBackupPoms=false
mvn clean install
mvn test 

 
