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
	 * Default TTL: 1 hour.
	 */
	public static final long DEFAULT_TTL_MILLIS = 3_600_000L;

	private static final Logger LOGGER = LoggerFactory.getLogger(ProviderCACache.class);
	private static final MessagesBundle coreMessagesBundle = new MessagesBundle();

	private static final ProviderCACache INSTANCE = new ProviderCACache();

	private final AtomicReference<CaSnapshot> snapshotRef = new AtomicReference<>();
	private final ReentrantLock loadLock = new ReentrantLock();

	private volatile long ttlMillis = resolveTtlFromConfig();

	private ProviderCACache() {
	}

	public static ProviderCACache getInstance() {
		return INSTANCE;
	}

	/**
	 * Immutable snapshot of the consolidated CA set for a given scope.
	 */
	private static final class CaSnapshot {
		private final List<X509Certificate> cas;
		private final String scopeKey;
		private final long loadedAtMillis;

		CaSnapshot(List<X509Certificate> cas, String scopeKey, long loadedAtMillis) {
			this.cas = cas;
			this.scopeKey = scopeKey;
			this.loadedAtMillis = loadedAtMillis;
		}
	}

	/**
	 * Result of a provider collection attempt, distinguishing a usable set from a
	 * total failure (so a failed load is never published as a valid, long-lived set).
	 */
	private static final class LoadResult {
		private final List<X509Certificate> cas;
		private final boolean usable;

		LoadResult(List<X509Certificate> cas, boolean usable) {
			this.cas = cas;
			this.usable = usable;
		}
	}

	/**
	 * Returns the consolidated CA set, loading/refreshing it if needed.
	 *
	 * @return an immutable list with the CAs of all enabled providers
	 */
	public List<X509Certificate> getCAs() {
		String scope = currentScopeKey();
		CaSnapshot current = snapshotRef.get();
		if (isValid(current, scope)) {
			return current.cas; // lock-free read
		}
		return loadAndPublish(scope);
	}

	private List<X509Certificate> loadAndPublish(String scope) {
		loadLock.lock();
		try {
			CaSnapshot current = snapshotRef.get(); // double-check inside the lock
			if (isValid(current, scope)) {
				return current.cas;
			}
			boolean scopeChanged = current != null && !current.scopeKey.equals(scope);

			LoadResult loaded = collectFromProviders();
			if (loaded.usable) {
				CaSnapshot fresh = new CaSnapshot(
						Collections.unmodifiableList(new ArrayList<>(loaded.cas)),
						scope,
						System.currentTimeMillis());
				snapshotRef.set(fresh); // atomic publication

				// When the CA set is (re)loaded, chains previously built over the old
				// set must not be reused (a CA may have been removed / is no longer
				// trusted). Invalidate the per-certificate chain cache in all cases:
				// first load (no-op in practice), scope change, or TTL refresh.
				CAManagerCache.getInstance().invalidate();

				LOGGER.debug("CA snapshot published: {} CA(s), scope={}, scopeChanged={}",
						fresh.cas.size(), scope, scopeChanged);
				return fresh.cas;
			}

			// Load failed: do not publish a failed/partial result as a valid set.
			if (current != null) {
				LOGGER.warn("Falha ao atualizar CAs; mantendo snapshot anterior ({} CA(s)).",
						current.cas.size());
				return current.cas;
			}
			LOGGER.error(coreMessagesBundle.getString("error.get.chain"));
			throw new CAManagerException(coreMessagesBundle.getString("error.get.chain"));
		} finally {
			loadLock.unlock();
		}
	}

	/**
	 * Collects the CAs from all enabled providers. Reuses the previous per-provider
	 * error handling of {@code CAManager}: a failure in one provider is logged and
	 * skipped. The result is only {@code usable} when at least one CA was collected
	 * and no provider failed catastrophically in a way that left the set empty.
	 */
	private LoadResult collectFromProviders() {
		List<X509Certificate> allCAs = new ArrayList<>();
		boolean anyProviderFailed = false;
		Collection<ProviderCA> providers = ProviderCAFactory.getInstance().factory();
		for (ProviderCA provider : providers) {
			long before = System.currentTimeMillis();
			try {
				Collection<X509Certificate> cas = provider.getCAs();
				if (cas != null) {
					allCAs.addAll(cas);
				}
				LOGGER.debug("Provider '{}' carregou {} CA(s) em {} ms",
						provider.getName(), cas == null ? 0 : cas.size(),
						System.currentTimeMillis() - before);
			} catch (Exception e) {
				anyProviderFailed = true;
				LOGGER.warn(coreMessagesBundle.getString("error.no.ca", provider.getName()));
			}
		}

		// Usable when we actually have CAs. An empty result caused by failures is not
		// publishable; an empty result with no failures is unexpected but also not useful.
		boolean usable = !allCAs.isEmpty();
		if (!usable && anyProviderFailed) {
			LOGGER.warn("Nenhuma CA carregada e houve falha de provider; snapshot nao sera publicado.");
		}
		return new LoadResult(allCAs, usable);
	}

	/**
	 * Explicitly invalidates the CA snapshot. The next {@link #getCAs()} will reload.
	 */
	public void invalidate() {
		snapshotRef.set(null);
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

	private boolean isValid(CaSnapshot snapshot, String scope) {
		if (snapshot == null || !snapshot.scopeKey.equals(scope)) {
			return false;
		}
		if (ttlMillis <= 0) {
			return true;
		}
		return (System.currentTimeMillis() - snapshot.loadedAtMillis) < ttlMillis;
	}

	/**
	 * Scope key = environment profile + sorted set of enabled provider class names.
	 * Changing {@code SIGNER_ENV} or enabling/disabling a chain changes the scope and
	 * forces a reload, preventing production and homologation CAs from mixing.
	 */
	private String currentScopeKey() {
		List<String> names = new ArrayList<>();
		for (ProviderCA provider : ProviderCAFactory.getInstance().factory()) {
			names.add(provider.getClass().getName());
		}
		Collections.sort(names);
		return "env=" + DisablingUtil.getEnvironment() + ";providers=" + names;
	}

	private static long resolveTtlFromConfig() {
		String value = System.getenv(ENV_CA_TTL_MILLIS);
		if (value == null || value.isEmpty()) {
			value = System.getProperty(CA_TTL_MILLIS);
		}
		if (value == null || value.isEmpty()) {
			return DEFAULT_TTL_MILLIS;
		}
		try {
			return Long.parseLong(value.trim());
		} catch (NumberFormatException e) {
			LOGGER.warn("Valor invalido para {} / {} ('{}'); usando default {} ms.",
					ENV_CA_TTL_MILLIS, CA_TTL_MILLIS, value, DEFAULT_TTL_MILLIS);
			return DEFAULT_TTL_MILLIS;
		}
	}
}
