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
import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class CAManagerCache {
	private static CAManagerCache instance;
	private Map<String, Collection<X509Certificate>> cachedCertificates = new ConcurrentHashMap<>();
	private Map<String, Boolean> isCAofCertificate = new ConcurrentHashMap<>();

	private CAManagerCache() {
	}

	public static synchronized CAManagerCache getInstance() {
		if (instance == null) {
			instance = new CAManagerCache();
		}
		return instance;
	}

	Collection<X509Certificate> getCachedCertificatesFor(X509Certificate certificate) {
		return cachedCertificates.get(getCertificateIdentificator(certificate));
	}

	void addCertificate(X509Certificate certificate, Collection<X509Certificate> certificates) {
		cachedCertificates.put(getCertificateIdentificator(certificate), certificates);
	}

	Boolean getIsCAofCertificate(X509Certificate ca, X509Certificate certificate) {
		String key = getCertificateIdentificator(ca) + "|" + getCertificateIdentificator(certificate);
		return isCAofCertificate.containsKey(key) ? isCAofCertificate.get(key) : null;
	}

	void setIsCAofCertificate(X509Certificate ca, X509Certificate certificate, boolean value) {
		String key = getCertificateIdentificator(ca) + "|" + getCertificateIdentificator(certificate);
		isCAofCertificate.put(key, value);
	}

	public void invalidate() {
		cachedCertificates.clear();
		isCAofCertificate.clear();
	}

	private String getCertificateIdentificator(X509Certificate certificate) {
		return certificate.getSubjectDN().getName() + certificate.getSerialNumber().toString();
	}
}
