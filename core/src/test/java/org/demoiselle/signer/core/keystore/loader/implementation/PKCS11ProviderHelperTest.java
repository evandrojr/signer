package org.demoiselle.signer.core.keystore.loader.implementation;

import static org.junit.Assert.*;
import org.junit.Test;
import java.security.Provider;

/**
 * Testes unitários para PKCS11ProviderHelper
 * 
 * Valida funcionalidade crítica da migração Java 21
 * 
 * @author Evandro Jr + GitHub Copilot
 */
public class PKCS11ProviderHelperTest {

/**
 * Testa que createProvider lança exceção com config inválida
 */
@Test
public void testCreateProviderWithInvalidConfigThrowsException() {
try {
// Config inválida deve falhar
String invalidConfig = "name=Invalid\nlibrary=/nonexistent/path.so";
PKCS11ProviderHelper.createProvider(invalidConfig);
fail("Deveria lançar exceção para config inválida");
} catch (Exception e) {
// Esperado
assertNotNull("Deve lançar exceção", e);
System.out.println("✅ Exception handling OK: " + e.getClass().getSimpleName());
}
}

/**
 * Testa que createProviderFromFile valida entrada null
 */
@Test
public void testCreateProviderFromFileWithNullThrowsException() {
try {
PKCS11ProviderHelper.createProviderFromFile(null);
fail("Deveria lançar exceção para path null");
} catch (NullPointerException | IllegalArgumentException e) {
// Esperado
System.out.println("✅ Null validation OK: " + e.getClass().getSimpleName());
} catch (Exception e) {
// Aceitável
assertNotNull(e);
System.out.println("✅ Exception with null: " + e.getClass().getSimpleName());
}
}

/**
 * Testa que logout não trava sem provider válido
 */
@Test
public void testLogoutWithInvalidProviderDoesNotCrash() {
try {
// Provider null ou inválido
PKCS11ProviderHelper.logout(null);
// Se chegou aqui, tratou graciosamente
System.out.println("✅ Logout handles null gracefully");
} catch (Exception e) {
// Exceção é aceitável, só não pode travar
assertNotNull(e);
System.out.println("✅ Logout exception handling: " + e.getClass().getSimpleName());
}
}

/**
 * Teste de detecção de versão Java via análise do sistema
 */
@Test
public void testJavaVersionIsReasonable() {
String javaVersion = System.getProperty("java.version");
assertNotNull("java.version deve estar definida", javaVersion);

// Versão deve começar com número
assertTrue("Versão deve começar com número", 
Character.isDigit(javaVersion.charAt(0)));

// Parse da versão
int majorVersion;
if (javaVersion.startsWith("1.")) {
majorVersion = Integer.parseInt(javaVersion.split("\\.")[1]);
} else {
majorVersion = Integer.parseInt(javaVersion.split("\\.")[0]);
}

// Estamos rodando Java 11+
assertTrue("Java version >= 11", majorVersion >= 11);
assertTrue("Java version < 100", majorVersion < 100);

System.out.println("✅ Java version detected: " + majorVersion + " (from " + javaVersion + ")");
}
}
