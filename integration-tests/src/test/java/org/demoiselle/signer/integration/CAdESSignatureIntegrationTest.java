package org.demoiselle.signer.integration;

import static org.junit.Assert.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;

import org.demoiselle.signer.policy.impl.cades.factory.PKCS7Factory;
import org.demoiselle.signer.policy.impl.cades.pkcs7.PKCS7Signer;
import org.junit.Before;
import org.junit.Test;
import org.junit.BeforeClass;

/**
 * Testes de integração para assinatura CAdES - Java 11+
 * 
 * Valida funcionalidade completa da biblioteca após migração
 * 
 * @author Evandro Jr + GitHub Copilot
 */
public class CAdESSignatureIntegrationTest {

    private static final String TEST_DATA_DIR = "target/test-data";
    private static final String TEST_FILE = TEST_DATA_DIR + "/document.txt";
    private static final String SIGNED_ATTACHED = TEST_DATA_DIR + "/document_attached.p7s";
    private static final String SIGNED_DETACHED = TEST_DATA_DIR + "/document_detached.p7s";
    
    @BeforeClass
    public static void setupClass() throws Exception {
        Files.createDirectories(Paths.get(TEST_DATA_DIR));
        System.out.println("=== TESTES DE INTEGRAÇÃO CADES - JAVA 11+ ===");
    }
    
    @Before
    public void setup() throws Exception {
        // Criar arquivo de teste
        String testContent = "Este é um documento de teste para assinatura digital.\n" +
                           "Projeto: Demoiselle Signer\n" +
                           "Migração: Java 7 → Java 11\n" +
                           "Data: 2026-01-23\n" +
                           "Status: Integração completa testada!\n";
        Files.write(Paths.get(TEST_FILE), testContent.getBytes());
    }
    
    /**
     * Teste 1: Assinatura CAdES Attached (conteúdo incluso)
     */
    @Test
    public void test01_CAdESAttachedSignature() throws Exception {
        System.out.println("\n=== TESTE 1: Assinatura CAdES Attached ===");
        
        // Carregar conteúdo
        byte[] content = Files.readAllBytes(Paths.get(TEST_FILE));
        System.out.println("📄 Arquivo: " + content.length + " bytes");
        
        // Criar keystore de teste
        KeyStore keyStore = createTestKeyStore();
        String alias = keyStore.aliases().nextElement();
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, "changeit".toCharArray());
        Certificate[] chain = keyStore.getCertificateChain(alias);
        
        System.out.println("🔑 Certificado: " + chain[0].toString().substring(0, 100) + "...");
        
        // Criar assinador
        PKCS7Signer signer = PKCS7Factory.getInstance().factoryDefault();
        signer.setCertificates(chain);
        signer.setPrivateKey(privateKey);
        
        // Assinar
        long start = System.currentTimeMillis();
        byte[] signature = signer.doAttachedSign(content);
        long duration = System.currentTimeMillis() - start;
        
        // Salvar
        try (FileOutputStream os = new FileOutputStream(SIGNED_ATTACHED)) {
            os.write(signature);
        }
        
        // Validações
        assertNotNull("Assinatura não deve ser null", signature);
        assertTrue("Assinatura deve ter tamanho > 0", signature.length > 0);
        assertTrue("Assinatura attached deve ser maior que original", 
                   signature.length > content.length);
        
        System.out.println("✅ Assinatura criada: " + signature.length + " bytes");
        System.out.println("✅ Tempo: " + duration + " ms");
        System.out.println("✅ Arquivo: " + SIGNED_ATTACHED);
    }
    
    /**
     * Teste 2: Assinatura CAdES Detached (apenas assinatura)
     */
    @Test
    public void test02_CAdESDetachedSignature() throws Exception {
        System.out.println("\n=== TESTE 2: Assinatura CAdES Detached ===");
        
        byte[] content = Files.readAllBytes(Paths.get(TEST_FILE));
        
        KeyStore keyStore = createTestKeyStore();
        String alias = keyStore.aliases().nextElement();
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, "changeit".toCharArray());
        Certificate[] chain = keyStore.getCertificateChain(alias);
        
        // Criar assinador
        PKCS7Signer signer = PKCS7Factory.getInstance().factoryDefault();
        System.setProperty("signer.certificate.validation.disabled", "true");
        signer.setCertificates(chain);
        signer.setPrivateKey(privateKey);
        
        // Assinar detached
        long start = System.currentTimeMillis();
        byte[] signature = signer.doDetachedSign(content);
        long duration = System.currentTimeMillis() - start;
        
        // Salvar
        try (FileOutputStream os = new FileOutputStream(SIGNED_DETACHED)) {
            os.write(signature);
        }
        
        assertNotNull("Assinatura detached não deve ser null", signature);
        assertTrue("Assinatura detached deve ter tamanho > 0", signature.length > 0);
        
        System.out.println("✅ Assinatura detached: " + signature.length + " bytes");
        System.out.println("✅ Tempo: " + duration + " ms");
        System.out.println("✅ Arquivo: " + SIGNED_DETACHED);
    }
    
    /**
     * Teste 3: Performance - Múltiplas assinaturas
     */
    @Test
    public void test03_PerformanceMultipleSignatures() throws Exception {
        System.out.println("\n=== TESTE 3: Performance - Múltiplas Assinaturas ===");
        
        byte[] content = Files.readAllBytes(Paths.get(TEST_FILE));
        KeyStore keyStore = createTestKeyStore();
        String alias = keyStore.aliases().nextElement();
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, "changeit".toCharArray());
        Certificate[] chain = keyStore.getCertificateChain(alias);
        
        int iterations = 5;
        long totalTime = 0;
        
        System.setProperty("signer.certificate.validation.disabled", "true");
        
        for (int i = 0; i < iterations; i++) {
            PKCS7Signer signer = PKCS7Factory.getInstance().factoryDefault();
            signer.setCertificates(chain);
            signer.setPrivateKey(privateKey);
            
            long start = System.currentTimeMillis();
            byte[] signature = signer.doAttachedSign(content);
            long duration = System.currentTimeMillis() - start;
            totalTime += duration;
            
            assertNotNull("Assinatura " + (i+1) + " não deve ser null", signature);
            System.out.println("  Assinatura " + (i+1) + ": " + duration + " ms");
        }
        
        double avgTime = totalTime / (double) iterations;
        
        System.out.println("✅ Total: " + iterations + " assinaturas");
        System.out.println("✅ Tempo total: " + totalTime + " ms");
        System.out.println("✅ Tempo médio: " + String.format("%.2f", avgTime) + " ms/assinatura");
        
        assertTrue("Tempo médio deve ser razoável (< 3s)", avgTime < 3000);
    }
    
    /**
     * Teste 4: Assinaturas com diferentes tamanhos de arquivo
     */
    @Test
    public void test04_DifferentFileSizes() throws Exception {
        System.out.println("\n=== TESTE 4: Diferentes Tamanhos de Arquivo ===");
        
        KeyStore keyStore = createTestKeyStore();
        String alias = keyStore.aliases().nextElement();
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, "changeit".toCharArray());
        Certificate[] chain = keyStore.getCertificateChain(alias);
        
        int[] sizes = {100, 1000, 10000, 100000};
        System.setProperty("signer.certificate.validation.disabled", "true");
        
        for (int size : sizes) {
            // Criar conteúdo de teste
            byte[] content = new byte[size];
            for (int i = 0; i < size; i++) {
                content[i] = (byte) ('A' + (i % 26));
            }
            
            PKCS7Signer signer = PKCS7Factory.getInstance().factoryDefault();
            signer.setCertificates(chain);
            signer.setPrivateKey(privateKey);
            
            long start = System.currentTimeMillis();
            byte[] signature = signer.doAttachedSign(content);
            long duration = System.currentTimeMillis() - start;
            
            assertNotNull("Assinatura não deve ser null", signature);
            
            System.out.println(String.format("  %6d bytes → %6d bytes (%d ms)", 
                                            size, signature.length, duration));
        }
        
        System.out.println("✅ Assinaturas com diferentes tamanhos OK");
    }
    
    /**
     * Teste 5: Validação de Java version
     */
    @Test
    public void test05_JavaVersionCompatibility() {
        System.out.println("\n=== TESTE 5: Compatibilidade Java ===");
        
        String javaVersion = System.getProperty("java.version");
        String javaVendor = System.getProperty("java.vendor");
        String javaHome = System.getProperty("java.home");
        
        System.out.println("☕ Java Version: " + javaVersion);
        System.out.println("☕ Java Vendor: " + javaVendor);
        System.out.println("☕ Java Home: " + javaHome);
        
        // Parse major version
        int majorVersion;
        if (javaVersion.startsWith("1.")) {
            majorVersion = Integer.parseInt(javaVersion.split("\\.")[1]);
        } else {
            majorVersion = Integer.parseInt(javaVersion.split("\\.")[0]);
        }
        
        assertTrue("Java version deve ser >= 11", majorVersion >= 11);
        System.out.println("✅ Versão compatível: Java " + majorVersion);
    }
    
    /**
     * Cria keystore de teste auto-assinado
     */
    private KeyStore createTestKeyStore() throws Exception {
        File ksFile = new File(TEST_DATA_DIR + "/test-keystore.jks");
        
        // Se já existe, apenas carregar
        if (ksFile.exists()) {
            KeyStore ks = KeyStore.getInstance("JKS");
            try (FileInputStream fis = new FileInputStream(ksFile)) {
                ks.load(fis, "changeit".toCharArray());
            }
            return ks;
        }
        
        // Criar novo com keytool
        ProcessBuilder pb = new ProcessBuilder(
            "keytool",
            "-genkeypair",
            "-alias", "testcert",
            "-keyalg", "RSA",
            "-keysize", "2048",
            "-validity", "365",
            "-keystore", ksFile.getAbsolutePath(),
            "-storepass", "changeit",
            "-keypass", "changeit",
            "-dname", "CN=Test User Java 11, OU=Integration Tests, O=Demoiselle Signer, L=Brasilia, ST=DF, C=BR"
        );
        
        Process process = pb.start();
        int exitCode = process.waitFor();
        
        if (exitCode != 0) {
            throw new RuntimeException("Falha ao criar keystore");
        }
        
        // Carregar e retornar
        KeyStore ks = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(ksFile)) {
            ks.load(fis, "changeit".toCharArray());
        }
        
        return ks;
    }
}
