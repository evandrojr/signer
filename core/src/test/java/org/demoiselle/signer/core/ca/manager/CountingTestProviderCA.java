package org.demoiselle.signer.core.ca.manager;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.demoiselle.signer.core.ca.provider.ProviderCA;

/**
 * Test {@link ProviderCA} that counts how many times {@code getCAs()} is called
 * and returns a fixed set of CAs. Registered via
 * {@code META-INF/services/org.demoiselle.signer.core.ca.provider.ProviderCA}
 * so {@link org.demoiselle.signer.core.ca.provider.ProviderCAFactory} picks it up
 * through the {@link java.util.ServiceLoader}.
 */
public class CountingTestProviderCA implements ProviderCA {

	public static final AtomicInteger CALL_COUNT = new AtomicInteger(0);
	public static volatile List<X509Certificate> cas = new ArrayList<>();
	public static volatile boolean throwOnLoad = false;

	public static void reset() {
		CALL_COUNT.set(0);
		throwOnLoad = false;
		cas = new ArrayList<>();
	}

	@Override
	public Collection<X509Certificate> getCAs() {
		CALL_COUNT.incrementAndGet();
		if (throwOnLoad) {
			throw new RuntimeException("simulated provider failure");
		}
		return new ArrayList<>(cas);
	}

	@Override
	public String getName() {
		return "CountingTestProviderCA";
	}
}
