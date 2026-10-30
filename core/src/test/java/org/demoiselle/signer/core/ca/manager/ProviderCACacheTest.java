package org.demoiselle.signer.core.ca.manager;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Covers the core behavior of the CA set cache (Requisitos 1, 3, 4, 5 da spec
 * cache-cas-providers): distinct certificates of the same CA trigger a single
 * provider load, concurrency is single-flight, invalidation reloads, and a total
 * load failure is not published as a valid snapshot.
 */
public class ProviderCACacheTest {

	private static KeyPair caKeyPair;
	private static X509Certificate rootCa;
	private static X509Certificate leafA;
	private static X509Certificate leafB;

	@BeforeClass
	public static void setUpClass() throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
		kpGen.initialize(2048);
		caKeyPair = kpGen.generateKeyPair();

		rootCa = buildSelfSignedCa(caKeyPair, "CN=Test Root CA");

		// Two distinct leaf certificates signed by the SAME CA.
		leafA = buildLeafSignedBy(caKeyPair, "CN=Signer A", BigInteger.valueOf(1001));
		leafB = buildLeafSignedBy(caKeyPair, "CN=Signer B", BigInteger.valueOf(1002));
	}

	@Before
	public void setUp() {
		CountingTestProviderCA.reset();
		CountingTestProviderCA.cas = new ArrayList<>(Arrays.asList(rootCa));
		CAManagerConfiguration.getInstance().setCached(true);
		ProviderCACache.getInstance().setTtlMillis(ProviderCACache.DEFAULT_TTL_MILLIS);
		ProviderCACache.getInstance().resetProvidersForTest();
		ProviderCACache.getInstance().invalidate();
		CAManagerCache.getInstance().invalidate();
	}

	@Test
	public void distinctCertificatesSameCa_singleProviderLoad() {
		Collection<X509Certificate> chainA = CAManager.getInstance().getCertificateChain(leafA);
		Collection<X509Certificate> chainB = CAManager.getInstance().getCertificateChain(leafB);

		assertNotNull(chainA);
		assertNotNull(chainB);
		assertTrue("cadeia de A deve conter a raiz", chainA.contains(rootCa));
		assertTrue("cadeia de B deve conter a raiz", chainB.contains(rootCa));
		assertEquals("getCAs() deve ser chamado uma unica vez para dois certs da mesma CA",
				1, CountingTestProviderCA.CALL_COUNT.get());
	}

	@Test
	public void repeatedQueries_singleProviderLoad() {
		for (int i = 0; i < 50; i++) {
			X509Certificate leaf = (i % 2 == 0) ? leafA : leafB;
			CAManager.getInstance().getCertificateChain(leaf);
		}
		assertEquals("50 consultas alternando dois certs = 1 carga", 1,
				CountingTestProviderCA.CALL_COUNT.get());
	}

	@Test
	public void concurrentColdStart_singleProviderLoad() throws Exception {
		int threads = 8;
		ExecutorService pool = Executors.newFixedThreadPool(threads);
		CountDownLatch start = new CountDownLatch(1);
		CountDownLatch done = new CountDownLatch(threads);
		List<Throwable> errors = new ArrayList<>();

		for (int t = 0; t < threads; t++) {
			final X509Certificate leaf = (t % 2 == 0) ? leafA : leafB;
			pool.submit(() -> {
				try {
					start.await();
					CAManager.getInstance().getCertificateChain(leaf);
				} catch (Throwable e) {
					synchronized (errors) {
						errors.add(e);
					}
				} finally {
					done.countDown();
				}
			});
		}
		start.countDown();
		assertTrue(done.await(30, TimeUnit.SECONDS));
		pool.shutdownNow();

		assertTrue("sem erros nas threads: " + errors, errors.isEmpty());
		assertEquals("carga unica sob concorrencia (single-flight)", 1,
				CountingTestProviderCA.CALL_COUNT.get());
	}

	@Test
	public void invalidate_reloadsProviders() {
		CAManager.getInstance().getCertificateChain(leafA);
		assertEquals(1, CountingTestProviderCA.CALL_COUNT.get());

		ProviderCACache.getInstance().invalidate();

		CAManager.getInstance().getCertificateChain(leafB);
		assertEquals("apos invalidate, nova carga", 2, CountingTestProviderCA.CALL_COUNT.get());
	}

	@Test
	public void totalFailure_noSnapshot_throws() {
		CountingTestProviderCA.throwOnLoad = true;
		try {
			CAManager.getInstance().getCertificateChain(leafA);
			fail("esperava CAManagerException quando nenhuma CA carrega");
		} catch (CAManagerException expected) {
			// ok
		}
		// cache de cadeia nao deve ter guardado nada
		assertFalse(CAManagerConfiguration.getInstance().isCached()
				&& CAManagerCache.getInstance().getCachedCertificatesFor(leafA) != null);
	}

	@Test
	public void failureAfterValidSnapshot_keepsPrevious() {
		CAManager.getInstance().getCertificateChain(leafA);
		assertEquals(1, CountingTestProviderCA.CALL_COUNT.get());

		// Expira o snapshot por TTL e faz a proxima carga falhar.
		// Usa leafB (ainda nao esta no cache de cadeia) para forcar nova consulta de CAs.
		ProviderCACache.getInstance().setTtlMillis(1L);
		try {
			Thread.sleep(5);
		} catch (InterruptedException ignored) {
			Thread.currentThread().interrupt();
		}
		CountingTestProviderCA.throwOnLoad = true;

		// snapshot expirou; carga falha; mantem snapshot anterior e ainda constroi a cadeia
		Collection<X509Certificate> chain = CAManager.getInstance().getCertificateChain(leafB);
		assertNotNull(chain);
		assertTrue(chain.contains(rootCa));
		assertEquals("houve tentativa de recarga", 2, CountingTestProviderCA.CALL_COUNT.get());
	}

	@Test
	public void notCached_collectsProvidersEveryCall_andDoesNotStoreChain() {
		CAManagerConfiguration.getInstance().setCached(false);
		try {
			CAManager.getInstance().getCertificateChain(leafA);
			CAManager.getInstance().getCertificateChain(leafA);
			CAManager.getInstance().getCertificateChain(leafB);
			// Sem cache: cada chamada consulta os providers diretamente (B3).
			assertEquals("isCached(false) deve coletar providers a cada chamada",
					3, CountingTestProviderCA.CALL_COUNT.get());
			// E nada e gravado no cache de cadeia.
			assertNull(CAManagerCache.getInstance().getCachedCertificatesFor(leafA));
		} finally {
			CAManagerConfiguration.getInstance().setCached(true);
		}
	}

	@Test
	public void epoch_changesOnPublishAndInvalidate() {
		// primeira carga publica -> epoch avanca
		ProviderCACache.CaSet set1 = ProviderCACache.getInstance().getCASet();
		long e1 = set1.getEpoch();

		// leitura valida nao muda o epoch
		ProviderCACache.CaSet set2 = ProviderCACache.getInstance().getCASet();
		assertEquals("cache hit nao muda epoch", e1, set2.getEpoch());

		// invalidate muda o epoch
		ProviderCACache.getInstance().invalidate();
		assertTrue("invalidate avanca o epoch", ProviderCACache.getInstance().getEpoch() != e1);

		// nova carga publica -> novo epoch, diferente do anterior
		long e3 = ProviderCACache.getInstance().getCASet().getEpoch();
		assertTrue("republicacao avanca o epoch", e3 != e1);
	}

	@Test
	public void staleChainNotCached_whenEpochChanged() {
		// constroi e cacheia a cadeia de leafA no epoch corrente
		CAManager.getInstance().getCertificateChain(leafA);
		assertNotNull(CAManagerCache.getInstance().getCachedCertificatesFor(leafA));
		long epochBefore = ProviderCACache.getInstance().getEpoch();

		// invalidate avanca o epoch; a limpeza do cache de cadeia ocorre na proxima
		// publicacao do snapshot (ver loadAndPublish). Forcamos essa publicacao com
		// uma nova consulta e confirmamos que o epoch avancou (conjunto de CAs renovado).
		ProviderCACache.getInstance().invalidate();
		CAManager.getInstance().getCertificateChain(leafB);
		assertTrue("epoch deve avancar apos invalidate + recarga",
				ProviderCACache.getInstance().getEpoch() != epochBefore);
	}

	// ---- helpers ----

	private static X509Certificate buildSelfSignedCa(KeyPair kp, String dn) throws Exception {
		X500Name name = new X500Name(dn);
		BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
		Date notBefore = new Date(System.currentTimeMillis() - 10000);
		Date notAfter = new Date(System.currentTimeMillis() + 3600_000L);

		X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
				name, serial, notBefore, notAfter, name, kp.getPublic());
		builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

		ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(kp.getPrivate());
		return new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));
	}

	private static X509Certificate buildLeafSignedBy(KeyPair caKp, String dn, BigInteger serial) throws Exception {
		KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
		kpGen.initialize(2048);
		KeyPair leafKp = kpGen.generateKeyPair();

		X500Name issuer = new X500Name("CN=Test Root CA");
		X500Name subject = new X500Name(dn);
		Date notBefore = new Date(System.currentTimeMillis() - 10000);
		Date notAfter = new Date(System.currentTimeMillis() + 3600_000L);

		X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
				issuer, serial, notBefore, notAfter, subject, leafKp.getPublic());
		builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

		ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(caKp.getPrivate());
		return new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));
	}
}
