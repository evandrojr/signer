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

package org.demoiselle.signer.core.util;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link DisablingUtil}.
 * <p>
 * Configuration model under test (positive/enable-based):
 * <ul>
 *   <li>{@code SIGNER_ENABLE_CHAIN_<NAME>} — per-chain override (final word, both directions)</li>
 *   <li>{@code SIGNER_ENV} — profile: prod (default) / hom / both (alias pro,hom)</li>
 *   <li>secure default — production loaded, homologation opt-in (skipped)</li>
 * </ul>
 */
class DisablingUtilTest {

    private Map<String, String> env() {
        return new HashMap<>();
    }

    private Map<String, String> env(String key, String value) {
        Map<String, String> map = new HashMap<>();
        map.put(key, value);
        return map;
    }

    // --- Secure defaults (nothing set) ---

    @Test
    void testDefault_productionChainEnabled() {
        assertFalse(DisablingUtil.isChainDisabled("icp-brasil", env()));
    }

    @Test
    void testDefault_homologationChainDisabled() {
        // Security default: homologation chains are opt-in, disabled when nothing is set.
        assertTrue(DisablingUtil.isChainDisabled("icp-brasil-homolog", env()));
    }

    // --- Per-chain enable override ---

    @Test
    void testEnableOverride_true_loadsChain() {
        assertFalse(DisablingUtil.isChainDisabled("icp-brasil-homolog",
                env("SIGNER_ENABLE_CHAIN_ICP_BRASIL_HOMOLOG", "true")));
    }

    @Test
    void testEnableOverride_false_skipsChain() {
        assertTrue(DisablingUtil.isChainDisabled("icp-brasil",
                env("SIGNER_ENABLE_CHAIN_ICP_BRASIL", "false")));
    }

    @Test
    void testEnableOverride_emptyValue_fallsBackToProfileDefault() {
        // Empty override is ignored; falls back to secure default (homolog opt-in).
        assertTrue(DisablingUtil.isChainDisabled("icp-brasil-homolog",
                env("SIGNER_ENABLE_CHAIN_ICP_BRASIL_HOMOLOG", "")));
    }

    @Test
    void testEnableOverride_beatsProfile_enableHomInProd() {
        // Production profile, but a specific homologation chain is explicitly enabled.
        Map<String, String> e = env();
        e.put("SIGNER_ENV", "prod");
        e.put("SIGNER_ENABLE_CHAIN_ICP_BRASIL_HOMOLOG", "true");
        assertFalse(DisablingUtil.isChainDisabled("icp-brasil-homolog", e));
    }

    @Test
    void testEnableOverride_beatsProfile_enableProInHom() {
        // Homologation profile, but a specific production chain is explicitly enabled.
        Map<String, String> e = env();
        e.put("SIGNER_ENV", "hom");
        e.put("SIGNER_ENABLE_CHAIN_ICP_BRASIL", "true");
        assertFalse(DisablingUtil.isChainDisabled("icp-brasil", e));
    }

    @Test
    void testEnableOverride_beatsProfile_disableProInProd() {
        // Production profile, but one production chain is explicitly disabled.
        Map<String, String> e = env();
        e.put("SIGNER_ENV", "prod");
        e.put("SIGNER_ENABLE_CHAIN_ICP_BRASIL", "false");
        assertTrue(DisablingUtil.isChainDisabled("icp-brasil", e));
    }

    // --- SIGNER_ENV=prod ---

    @Test
    void testEnvProd_productionEnabled_homologationDisabled() {
        assertFalse(DisablingUtil.isChainDisabled("icp-brasil", env("SIGNER_ENV", "prod")));
        assertTrue(DisablingUtil.isChainDisabled("icp-brasil-homolog", env("SIGNER_ENV", "production")));
    }

    // --- SIGNER_ENV=hom ---

    @Test
    void testEnvHom_homologationEnabled_productionDisabled() {
        assertFalse(DisablingUtil.isChainDisabled("icp-brasil-homolog", env("SIGNER_ENV", "hom")));
        assertTrue(DisablingUtil.isChainDisabled("icp-brasil", env("SIGNER_ENV", "homolog")));
    }

    // --- SIGNER_ENV=both ---

    @Test
    void testEnvBoth_loadsProductionAndHomologation() {
        assertFalse(DisablingUtil.isChainDisabled("icp-brasil", env("SIGNER_ENV", "both")));
        assertFalse(DisablingUtil.isChainDisabled("icp-brasil-homolog", env("SIGNER_ENV", "both")));
    }

    @Test
    void testEnvBoth_commaListAlias() {
        assertFalse(DisablingUtil.isChainDisabled("icp-brasil", env("SIGNER_ENV", "pro,hom")));
        assertFalse(DisablingUtil.isChainDisabled("icp-brasil-homolog", env("SIGNER_ENV", "hom,pro")));
        // spaces tolerated
        assertFalse(DisablingUtil.isChainDisabled("icp-brasil-homolog", env("SIGNER_ENV", "pro, hom")));
    }

    // --- helpers ---

    @Test
    void testIsChainEnabled_isInverseOfIsChainDisabled() {
        assertTrue(DisablingUtil.isChainEnabled("icp-brasil"));
        assertFalse(DisablingUtil.isChainEnabled("icp-brasil-homolog"));
    }

    @Test
    void testToEnableVariableName() {
        assertEquals("SIGNER_ENABLE_CHAIN_ICP_BRASIL_HOMOLOG",
                DisablingUtil.toEnableVariableName("icp-brasil-homolog"));
        assertEquals("SIGNER_ENABLE_CHAIN_ITI_HOMOLOG",
                DisablingUtil.toEnableVariableName("iti-homolog"));
        assertEquals("SIGNER_ENABLE_CHAIN_SERPRO_NEOSIGNER_HOMOLOG",
                DisablingUtil.toEnableVariableName("serpro-neosigner-homolog"));
    }

    @Test
    void testGetEnvironment_empty_default() {
        assertEquals("", DisablingUtil.getEnvironment(env()));
    }

    @Test
    void testGetEnvironment_withValue() {
        assertEquals("hom", DisablingUtil.getEnvironment(env("SIGNER_ENV", "hom")));
    }
}
