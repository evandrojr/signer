/*
 * Demoiselle Framework
 * Copyright (C) 2010 SERPRO
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

package org.demoiselle.signer.chain.icp.brasil.provider.impl;

import org.demoiselle.signer.core.repository.ConfigurationRepo;
import org.junit.Test;

import java.security.cert.X509Certificate;
import java.util.Collection;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertNotNull;

public class ICPBrasilOnLineSerproProviderCATest {

	private final ICPBrasilOnLineSerproProviderCA provider =
		new ICPBrasilOnLineSerproProviderCA();

	@Test
	public void checkNameOfProvider() {
		assertTrue(provider.getName().contains("serpro"));
	}

	@Test
	public void obtemCertificados() {
		Collection<X509Certificate> cas = provider.getCAs();
		assertTrue(cas.size() > 100);
	}

	/**
	 * Req 2.5 / B? — Em modo offline (isOnline=false) o provider NAO deve consultar
	 * hash remoto nem baixar o ZIP: usa apenas o artefato local. O teste confirma que
	 * a chamada retorna uma colecao nao-nula sem lancar e sem incorrer na latencia de
	 * rede (bem abaixo do timeout de download de cadeia).
	 */
	@Test
	public void offline_naoVaiAhRede() {
		ConfigurationRepo repo = ConfigurationRepo.getInstance();
		boolean onlineAnterior = repo.isOnline();
		repo.setOnline(false);
		try {
			long before = System.currentTimeMillis();
			Collection<X509Certificate> cas = provider.getCAs();
			long elapsed = System.currentTimeMillis() - before;

			assertNotNull("getCAs() nunca retorna null", cas);
			// Sem rede: deve completar muito antes do timeout de download de cadeia.
			assertTrue("modo offline nao deve pagar latencia de rede (levou " + elapsed + " ms)",
					elapsed < repo.getCaChainTimeOut());
		} finally {
			repo.setOnline(onlineAnterior);
		}
	}
}
