/*
 * Demoiselle Framework
 * Copyright (C) 2021 SERPRO
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

package org.demoiselle.signer.chain.serpro.neosigner.provider;

import java.io.InputStream;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import org.demoiselle.signer.core.ca.provider.ProviderCA;
import org.demoiselle.signer.core.util.DisablingUtil;
import org.demoiselle.signer.core.util.MessagesBundle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provides Certificate Authority chain of SERPRO (both production and homologation).
 * <p>
 * By default, only the production chain is loaded. <strong>The homologation chain is
 * opt-in for security reasons</strong> (homologation certificates come from test
 * authorities and must not be trusted in production).
 * <p>
 * To skip the entire provider, set: {@code SIGNER_ENABLE_CHAIN_SERPRO_NEOSIGNER=false}
 * <p>
 * Each sub-chain follows the standard resolution
 * (per-chain override &gt; {@code SIGNER_ENV} profile &gt; secure default):
 * <ul>
 *   <li>Production sub-chain: {@code SIGNER_ENABLE_CHAIN_SERPRO_NEOSIGNER_PROD}</li>
 *   <li>Homologation sub-chain: {@code SIGNER_ENABLE_CHAIN_SERPRO_NEOSIGNER_HOMOLOG}</li>
 * </ul>
 * For example, {@code SIGNER_ENV=both} loads both sub-chains; {@code SIGNER_ENV=hom} loads
 * only homologation; {@code SIGNER_ENABLE_CHAIN_SERPRO_NEOSIGNER_HOMOLOG=true} loads the
 * homologation sub-chain on top of a production profile.
 */
public class SerproNeoSignerProviderCA implements ProviderCA {

        protected static MessagesBundle chainMessagesBundle = new MessagesBundle();
        private static final Logger logger = LoggerFactory.getLogger(SerproNeoSignerProviderCA.class);

        @SuppressWarnings("finally")
        public Collection<X509Certificate> getCAs() {
                if (DisablingUtil.isChainDisabled("serpro-neosigner")) {
                        logger.info("Provider 'serpro-neosigner' is disabled. Skipping CA loading.");
                        return new ArrayList<>();
                }
                List<X509Certificate> result = new ArrayList<>();
                try {
                        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
                        CertificateFactory factory = CertificateFactory.getInstance("X.509", "BC");

                        // Cada sub-cadeia usa a resolucao central do DisablingUtil:
                        // override por cadeia > perfil SIGNER_ENV > padrao seguro
                        // (producao carregada, homologacao opt-in).
                        boolean loadProduction = DisablingUtil.isChainEnabled("serpro-neosigner-prod");
                        boolean loadHomologation = DisablingUtil.isChainEnabled("serpro-neosigner-homolog");

                        if (loadProduction) {
                                logger.info("Carregando cadeias de producao do SERPRO (NeoSigner).");
                                loadCert(result, factory, "trustedca/AutoridadeCertificadoraAssinadorSERPRORaiz.crt");
                                loadCert(result, factory, "trustedca/AutoridadeCertificadoraAssinadorSERPROFinal.crt");
                        }

                        if (loadHomologation) {
                                logger.info("Carregando cadeias de homologacao do SERPRO (NeoSigner).");
                                loadCert(result, factory, "trustedca/AutoridadeCertificadoraRaizdoSERPRO.crt");
                                loadCert(result, factory, "trustedca/AutoridadeCertificadoraFinaldoSERPRO.crt");
                                loadCert(result, factory, "trustedca/AutoridadeCertificadoraRaizdoSERPROSoftware.crt");
                                loadCert(result, factory, "trustedca/AutoridadeCertificadoraFinaldoSERPROSoftware.crt");
                                loadCert(result, factory, "trustedca/NeoSignerSERPRO.crt");
                        }
                } catch (Throwable error) {
                        logger.error("Erro ao carregar CAs do NeoSigner: " + error.getMessage());
                } finally {
                        return result;
                }
        }

        private void loadCert(List<X509Certificate> result, CertificateFactory factory, String path) {
                try {
                        InputStream is = SerproNeoSignerProviderCA.class.getClassLoader().getResourceAsStream(path);
                        if (is != null) {
                                result.add((X509Certificate) factory.generateCertificate(is));
                        }
                } catch (Exception e) {
                        logger.error("Erro ao carregar certificado " + path + ": " + e.getMessage());
                }
        }

        public String getName() {
                return chainMessagesBundle.getString("info.provider.name.serpro.neosigner");
        }
}
