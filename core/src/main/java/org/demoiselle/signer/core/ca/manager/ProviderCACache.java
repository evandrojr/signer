/*
 * Demoiselle Framework
 * Copyright (C) 2016 SERPRO
 * ----------------------------------------------------------------------------
 * This file is part of Demoiselle Framework.
 *
 * Demoiselle Framework is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License version 3
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License version 3
 * along with this program; if not,  see <http://www.gnu.org/licenses/>
 * or write to the Free Software Foundation, Inc., 51 Franklin Street,
 * Fifth Floor, Boston, MA  02110-1301, USA.
 * ----------------------------------------------------------------------------
 * Este arquivo é parte do Framework Demoiselle.
 *
 * O Framework Demoiselle é um software livre; você pode redistribuí-lo e/ou
 * modificá-lo dentro dos termos da GNU LGPL versão 3 como publicada pela Fundação
 * do Software Livre (FSF).
 *
 * Este programa é distribuído na esperança que possa ser útil, mas SEM NENHUMA
 * GARANTIA; sem uma garantia implícita de ADEQUAÇÃO a qualquer MERCADO ou
 * APLICAÇÃO EM PARTICULAR. Veja a Licença Pública Geral GNU/LGPL em português
 * para maiores detalhes.
 *
 * Você deve ter recebido uma cópia da GNU LGPL versão 3, sob o título
 * "LICENCA.txt", junto com esse programa. Se não, acesse <http://www.gnu.org/licenses/>
 * ou escreva para a Fundação do Software Livre (FSF) Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA 02111-1301, USA.
 */

package org.demoiselle.signer.core.ca.manager;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;

import org.demoiselle.signer.core.ca.provider.ProviderCA;
import org.demoiselle.signer.core.ca.provider.ProviderCAFactory;
import org.demoiselle.signer.core.util.DisablingUtil;
import org.demoiselle.signer.core.util.MessagesBundle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Cache of the consolidated set of Certificate Authorities (CAs) provided by all
 * enabled {@link ProviderCA}s.
 * <p>
 * This cache is distinct from {@link CAManagerCache}, which caches the chain built
 * for each individual certificate. Here we keep the union of {@code getCAs()} from
 * every enabled provider so that validating a <em>new</em> certificate whose chain
 * is already served by the available CAs does NOT trigger a reload of all providers
 * (no network/ZIP work per unknown certificate).
 * <p>
 * Concurrency: reads of a valid snapshot are lock-free (via {@link AtomicReference}).
 * Only a (re)load is serialized through a dedicated {@link ReentrantLock}, so the
 * provider loading and its network operations do not block chain lookups whose
 * certificate is already cached.
 * <p>
 * Expiration: controlled by a TTL (default 1 hour), configurable via
 * {@code SIGNER_CAMANAGER_CA_TTL_MILLIS} env var or {@code signer.camanager.ca.ttl.millis}
 * system property. A value of {@code 0} (or negative) disables time expiration; the
 * snapshot is then only refreshed when the scope (environment / enabled providers)
 * changes or {@link #invalidate()} is called explicitly.
 */
public final class ProviderCACache {

	/**
	 * System key to set the CA snapshot TTL in milliseconds.
	 */
	public static final String CA_TTL_MILLIS = "signer.camanager.ca.ttl.millis";

	/**
	 * System environment key to set the CA snapshot TTL in milliseconds.
	 */
	public static final String ENV_CA_TTL_MILLIS = "SIGNER_CAMANAGER_CA_TTL_MILLIS";

	/**
	 * System key to set the maximum stale window (in ms) after the TTL expires while
	 * provider reloads keep failing. Bounds how long an expired snapshot may still be
	 * served before failing closed. See R2-2 in the review.
	 */
	public static final String CA_MAX_STALE_MILLIS = "signer.camanager.ca.max.stale.millis";

	/**
	 * System environment key to set the maximum stale window in milliseconds.
	 */
	public static final String ENV_CA_MAX_STALE_MILLIS = "SIGNER_CAMANAGER_CA_MAX_STALE_MILLIS";

	/**
	 * Default TTL: 1 hour.
	 */
	public static final long DEFAULT_TTL_MILLIS = 3_600_000L;

	/**
	 * Default maximum stale window after TTL expiry: 1 hour (so the absolute trust
	 * window is at most TTL + max stale = 2 hours under a sustained provider outage).
	 */
	public static final long DEFAULT_MAX_STALE_MILLIS = 3_600_000L;

	/**
	 * System key to set the short TTL (in ms) used for a <em>degraded</em> snapshot, i.e.
	 * one built while some provider failed. It keeps availability (using the CAs that
	 * did load) without caching a partial set for the whole normal TTL. See R2-1.
	 */
	public static final String CA_DEGRADED_TTL_MILLIS = "signer.camanager.ca.degraded.ttl.millis";

	/**
	 * System environment key to set the degraded snapshot TTL in milliseconds.
	 */
	public static final String ENV_CA_DEGRADED_TTL_MILLIS = "SIGNER_CAMANAGER_CA_DEGRADED_TTL_MILLIS";

	/**
	 * Default degraded TTL: 1 minute (partial results are retried quickly).
	 */
	public static final long DEFAULT_DEGRADED_TTL_MILLIS = 60_000L;

	/**
	 * Known chain names whose enable/disable state (via {@code SIGNER_ENABLE_CHAIN_*}
	 * or {@code SIGNER_ENV}) must be part of the cache scope. Keep in sync with the
	 * chain modules / {@link DisablingUtil} usage across providers.
	 */
	private static final String[] KNOWN_CHAINS = {
			"icp-brasil",
			"icp-brasil-homolog",
			"iti-homolog",
			"serpro-neosigner",
			"serpro-neosigner-prod",
			"serpro-neosigner-homolog"
	};

	private static final Logger LOGGER = LoggerFactory.getLogger(ProviderCACache.class);
	private static final MessagesBundle coreMessagesBundle = new MessagesBundle();

	private static final ProviderCACache INSTANCE = new ProviderCACache();

	private final AtomicReference<CaSnapshot> snapshotRef = new AtomicReference<>();
	private final ReentrantLock loadLock = new ReentrantLock();

	// Monitor shared by epoch invariants: publication/invalidation and the guarded
	// chain-cache write must be atomic with respect to each other (see I1/R2-3).
	private final Object epochMonitor = new Object();

	private volatile long ttlMillis = resolveTtlFromConfig();
	private volatile long maxStaleMillis = resolveMaxStaleFromConfig();
	private volatile long degradedTtlMillis = resolveDegradedTtlFromConfig();

	// Epoch incrementado a cada publicacao/invalidacao do snapshot de CAs.
	// Usado para detectar que o conjunto de CAs mudou entre a leitura das CAs
	// e a gravacao da cadeia no cache por certificado (ver CAManager + I1).
	private final AtomicLong epoch = new AtomicLong(0);

	// Providers resolvidos uma unica vez (ServiceLoader e caro e os providers
	// sao estaticos durante o ciclo de vida do classloader). Ver I2.
	private volatile List<ProviderCA> cachedProviders;

	private ProviderCACache() {
	}

	public static ProviderCACache getInstance() {
		return INSTANCE;
	}

	/**
	 * Snapshot das CAs juntamente com o epoch em que foi obtido. Permite ao chamador
	 * (CAManager) descartar a gravacao de uma cadeia construida sobre um conjunto de
	 * CAs que ja foi substituido/invalidado por outra thread.
	 */
	public static final class CaSet {
		private final List<X509Certificate> cas;
		private final long epoch;

		CaSet(List<X509Certificate> cas, long epoch) {
			this.cas = cas;
			this.epoch = epoch;
		}

		public List<X509Certificate> getCAs() {
			return cas;
		}

		public long getEpoch() {
			return epoch;
		}
	}

	/**
	 * Immutable snapshot of the consolidated CA set for a given scope.
	 */
	private static final class CaSnapshot {
		private final List<X509Certificate> cas;
		private final String scopeKey;
		private final long loadedAtMillis;
		private final long epoch;
		private final boolean degraded;

		CaSnapshot(List<X509Certificate> cas, String scopeKey, long loadedAtMillis, long epoch,
				boolean degraded) {
			this.cas = cas;
			this.scopeKey = scopeKey;
			this.loadedAtMillis = loadedAtMillis;
			this.epoch = epoch;
			this.degraded = degraded;
		}
	}

	/**
	 * Result of a provider collection attempt, distinguishing a usable set from a
	 * partial/total failure (so a failed load is never published as a valid, long-lived set).
	 */
	private static final class LoadResult {
		private final List<X509Certificate> cas;
		private final boolean usable;
		private final boolean anyFailed;

		LoadResult(List<X509Certificate> cas, boolean usable, boolean anyFailed) {
			this.cas = cas;
			this.usable = usable;
			this.anyFailed = anyFailed;
		}
	}

	/**
	 * Returns the consolidated CA set, loading/refreshing it if needed.
	 *
	 * @return an immutable list with the CAs of all enabled providers
	 */
	public List<X509Certificate> getCAs() {
		return getCASet().getCAs();
	}

	/**
	 * Returns the consolidated CA set together with the epoch in which it was taken,
	 * so callers can detect a concurrent refresh/invalidation before persisting work
	 * derived from these CAs (see {@link #getEpoch()} and I1 in the review).
	 *
	 * @return the CA set and its epoch
	 */
	public CaSet getCASet() {
		String scope = currentScopeKey();
		CaSnapshot current = snapshotRef.get();
		if (isValid(current, scope)) {
			return new CaSet(current.cas, current.epoch); // lock-free read
		}
		return loadAndPublish(scope);
	}

	/**
	 * @return the current epoch; changes on every snapshot publication or invalidation
	 */
	public long getEpoch() {
		return epoch.get();
	}

	private CaSet loadAndPublish(String scope) {
		loadLock.lock();
		try {
			CaSnapshot current = snapshotRef.get(); // double-check inside the lock
			if (isValid(current, scope)) {
				return new CaSet(current.cas, current.epoch);
			}
			boolean scopeChanged = current != null && !current.scopeKey.equals(scope);

			LoadResult loaded = collectFromProviders();
			if (loaded.usable) {
				long newEpoch;
				CaSnapshot fresh;
				synchronized (epochMonitor) {
					newEpoch = epoch.incrementAndGet();
					fresh = new CaSnapshot(
							Collections.unmodifiableList(new ArrayList<>(loaded.cas)),
							scope,
							System.currentTimeMillis(),
							newEpoch,
							loaded.anyFailed);
					snapshotRef.set(fresh); // atomic publication

					// When the CA set is (re)loaded, chains previously built over the old
					// set must not be reused (a CA may have been removed / is no longer
					// trusted). Invalidate the per-certificate chain cache in all cases:
					// first load (no-op in practice), scope change, or TTL refresh.
					CAManagerCache.getInstance().invalidate();
				}

				if (fresh.degraded) {
					LOGGER.warn("Snapshot de CAs publicado em modo DEGRADADO ({} CA(s)): ao menos um provider "
							+ "falhou; nova tentativa em ate {} ms.", fresh.cas.size(), degradedTtlMillis);
				}
				LOGGER.debug("CA snapshot published: {} CA(s), scope={}, scopeChanged={}, epoch={}, degraded={}",
						fresh.cas.size(), scope, scopeChanged, newEpoch, fresh.degraded);
				return new CaSet(fresh.cas, newEpoch);
			}

			// Load failed (partial or total): do not publish a failed/partial result
			// as a valid set. Keep the previous snapshot only while it is within the
			// bounded stale window; after that, fail closed instead of serving a
			// possibly-stale trust set forever (see R2-2 in the review).
			if (current != null) {
				long age = System.currentTimeMillis() - current.loadedAtMillis;
				if (ttlMillis <= 0 || age <= ttlMillis + maxStaleMillis) {
					LOGGER.warn("Falha/parcial ao atualizar CAs; mantendo snapshot anterior ({} CA(s), idade {} ms).",
							current.cas.size(), age);
					return new CaSet(current.cas, current.epoch);
				}
				LOGGER.error("Falha ao atualizar CAs e snapshot anterior excedeu a janela de stale ({} ms); "
						+ "descartando para nao servir conjunto potencialmente obsoleto.", age);
				synchronized (epochMonitor) {
					epoch.incrementAndGet();
					snapshotRef.compareAndSet(current, null);
				}
			}
			LOGGER.error(coreMessagesBundle.getString("error.get.chain"));
			throw new CAManagerException(coreMessagesBundle.getString("error.get.chain"));
		} finally {
			loadLock.unlock();
		}
	}

	/**
	 * Collects the CAs from all enabled providers. A failure in one provider is logged
	 * and flagged in the result.
	 * <p>
	 * A non-empty union is still publishable when some provider failed (availability:
	 * the CAs that did load are used), but it is marked as <em>degraded</em> and gets a
	 * short TTL so the partial set is retried soon instead of being cached for the whole
	 * normal TTL (see B2/R2-1 in the review). An empty union is never publishable.
	 */
	private LoadResult collectFromProviders() {
		List<X509Certificate> allCAs = new ArrayList<>();
		boolean anyProviderFailed = false;
		for (ProviderCA provider : getProviders()) {
			long before = System.currentTimeMillis();
			try {
				Collection<X509Certificate> cas = provider.getCAs();
				if (cas == null) {
					anyProviderFailed = true;
					LOGGER.warn("Provider '{}' retornou null; tratado como falha.", provider.getName());
					continue;
				}
				allCAs.addAll(cas);
				LOGGER.debug("Provider '{}' carregou {} CA(s) em {} ms",
						provider.getName(), cas.size(), System.currentTimeMillis() - before);
			} catch (Exception e) {
				anyProviderFailed = true;
				LOGGER.warn(coreMessagesBundle.getString("error.no.ca", provider.getName()));
			}
		}

		boolean usable = !allCAs.isEmpty();
		if (anyProviderFailed) {
			if (usable) {
				LOGGER.warn("Falha em ao menos um provider; publicando snapshot DEGRADADO com {} CA(s) "
						+ "dos providers que responderam.", allCAs.size());
			} else {
				LOGGER.warn("Falha em ao menos um provider e nenhuma CA carregada; snapshot nao sera publicado.");
			}
		} else if (!usable) {
			LOGGER.warn("Nenhuma CA carregada; snapshot nao sera publicado.");
		}
		return new LoadResult(allCAs, usable, anyProviderFailed);
	}

	/**
	 * Explicitly invalidates the CA snapshot. The next {@link #getCAs()} will reload.
	 * Also bumps the epoch so in-flight chain builds over the old set are not persisted.
	 */
	public void invalidate() {
		synchronized (epochMonitor) {
			epoch.incrementAndGet();
			snapshotRef.set(null);
		}
	}

	/**
	 * Runs {@code action} atomically only if the current epoch still equals
	 * {@code expectedEpoch}. Because publication/invalidation also mutate the epoch
	 * and the chain cache under the same monitor, this closes the check-then-act race
	 * window that could otherwise re-insert a stale chain after a concurrent refresh
	 * (see I1 / R2-3 in the review).
	 *
	 * @param expectedEpoch epoch observed when the work was derived from the CA set
	 * @param action        work to run (e.g., persist the built chain)
	 * @return {@code true} if the action ran, {@code false} if the epoch changed
	 */
	public boolean runIfEpochUnchanged(long expectedEpoch, Runnable action) {
		synchronized (epochMonitor) {
			if (epoch.get() != expectedEpoch) {
				return false;
			}
			action.run();
			return true;
		}
	}

	/**
	 * Forces re-resolution of providers on the next load. Package-private, intended
	 * for tests that register/replace providers via ServiceLoader at runtime.
	 */
	void resetProvidersForTest() {
		synchronized (this) {
			cachedProviders = null;
		}
	}

	/**
	 * @return the configured TTL in milliseconds
	 */
	public long getTtlMillis() {
		return ttlMillis;
	}

	/**
	 * Overrides the TTL at runtime (mainly for tests / explicit policy).
	 *
	 * @param ttlMillis new TTL; 0 or negative disables time expiration
	 */
	public void setTtlMillis(long ttlMillis) {
		this.ttlMillis = ttlMillis;
	}

	/**
	 * @return the maximum stale window (ms) after the TTL expires while reloads fail
	 */
	public long getMaxStaleMillis() {
		return maxStaleMillis;
	}

	/**
	 * Overrides the maximum stale window at runtime (mainly for tests / explicit policy).
	 *
	 * @param maxStaleMillis new window; 0 means fail closed immediately after the TTL
	 */
	public void setMaxStaleMillis(long maxStaleMillis) {
		this.maxStaleMillis = maxStaleMillis;
	}

	/**
	 * @return the short TTL (ms) used while a snapshot is degraded by provider failures
	 */
	public long getDegradedTtlMillis() {
		return degradedTtlMillis;
	}

	/**
	 * Overrides the degraded snapshot TTL at runtime (mainly for tests).
	 *
	 * @param degradedTtlMillis new TTL; values &lt;= 0 fall back to the default
	 */
	public void setDegradedTtlMillis(long degradedTtlMillis) {
		this.degradedTtlMillis = degradedTtlMillis;
	}

	private boolean isValid(CaSnapshot snapshot, String scope) {
		if (snapshot == null || !snapshot.scopeKey.equals(scope)) {
			return false;
		}
		long effectiveTtl = snapshot.degraded ? degradedTtlMillis : ttlMillis;
		if (snapshot.degraded && effectiveTtl <= 0) {
			// A degraded (partial) snapshot must never be cached indefinitely.
			effectiveTtl = DEFAULT_DEGRADED_TTL_MILLIS;
		}
		if (effectiveTtl <= 0) {
			return true;
		}
		return (System.currentTimeMillis() - snapshot.loadedAtMillis) < effectiveTtl;
	}

	/**
	 * Scope key = environment profile + enabled/disabled state of each known chain +
	 * sorted provider class names. Changing {@code SIGNER_ENV} OR any per-chain
	 * override ({@code SIGNER_ENABLE_CHAIN_*}) changes the scope and forces a reload,
	 * preventing production and homologation CAs from mixing and preventing a stale
	 * snapshot from being reused when a chain is enabled/disabled (see B1 in the review).
	 * <p>
	 * Note: env vars / system properties are read at load time and do not change at
	 * runtime in a running JVM, so this is still deterministic per process; the state
	 * is included so distinct configurations never share a snapshot.
	 */
	private String currentScopeKey() {
		List<String> names = new ArrayList<>();
		for (ProviderCA provider : getProviders()) {
			names.add(provider.getClass().getName());
		}
		Collections.sort(names);

		// Estado de habilitacao de cada cadeia conhecida (ordenado para estabilidade).
		// Reflete os overrides SIGNER_ENABLE_CHAIN_* alem do perfil SIGNER_ENV.
		StringBuilder chains = new StringBuilder();
		for (String chain : KNOWN_CHAINS) {
			chains.append(chain).append('=')
					.append(DisablingUtil.isChainDisabled(chain) ? "off" : "on").append(',');
		}

		return "env=" + DisablingUtil.getEnvironment()
				+ ";chains=[" + chains + "]"
				+ ";providers=" + names;
	}

	/**
	 * Resolve providers once per classloader lifecycle. {@code ServiceLoader} is
	 * relatively expensive and instantiates every provider; doing it on every
	 * {@code getCAs()} (including cache hits) was wasteful and could re-run provider
	 * constructors with side effects (see I2 in the review).
	 */
	private List<ProviderCA> getProviders() {
		List<ProviderCA> local = cachedProviders;
		if (local == null) {
			synchronized (this) {
				local = cachedProviders;
				if (local == null) {
					local = new ArrayList<>(ProviderCAFactory.getInstance().factory());
					cachedProviders = local;
				}
			}
		}
		return local;
	}

	private static long resolveTtlFromConfig() {
		return resolveMillisFromConfig(ENV_CA_TTL_MILLIS, CA_TTL_MILLIS, DEFAULT_TTL_MILLIS);
	}

	private static long resolveMaxStaleFromConfig() {
		return resolveMillisFromConfig(ENV_CA_MAX_STALE_MILLIS, CA_MAX_STALE_MILLIS, DEFAULT_MAX_STALE_MILLIS);
	}

	private static long resolveDegradedTtlFromConfig() {
		return resolveMillisFromConfig(ENV_CA_DEGRADED_TTL_MILLIS, CA_DEGRADED_TTL_MILLIS,
				DEFAULT_DEGRADED_TTL_MILLIS);
	}

	private static long resolveMillisFromConfig(String envKey, String sysKey, long defaultValue) {
		String value = System.getenv(envKey);
		if (value == null || value.isEmpty()) {
			value = System.getProperty(sysKey);
		}
		if (value == null || value.isEmpty()) {
			return defaultValue;
		}
		try {
			return Long.parseLong(value.trim());
		} catch (NumberFormatException e) {
			LOGGER.warn("Valor invalido para {} / {} ('{}'); usando default {} ms.",
					envKey, sysKey, value, defaultValue);
			return defaultValue;
		}
	}
}
