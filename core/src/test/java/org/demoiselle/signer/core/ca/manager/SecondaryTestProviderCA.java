package org.demoiselle.signer.core.ca.manager;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.demoiselle.signer.core.ca.provider.ProviderCA;

/**
 * Second test {@link ProviderCA}, registered alongside {@link CountingTestProviderCA}
 * via the ServiceLoader, used to exercise the partial/degraded snapshot path (one
 * provider succeeds while another throws). By default it succeeds with an empty set,
 * so it does not interfere with the other scenarios.
 */
public class SecondaryTestProviderCA implements ProviderCA {

	public static volatile List<X509Certificate> cas = new ArrayList<>();
	public static volatile boolean throwOnLoad = false;

	public static void reset() {
		cas = new ArrayList<>();
		throwOnLoad = false;
	}

	@Override
	public Collection<X509Certificate> getCAs() {
		if (throwOnLoad) {
			throw new RuntimeException("simulated secondary provider failure");
		}
		return new ArrayList<>(cas);
	}

	@Override
	public String getName() {
		return "SecondaryTestProviderCA";
	}
}
