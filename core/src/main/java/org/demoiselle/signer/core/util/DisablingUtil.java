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

import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility class that decides which certificate chains should be loaded, based on
 * environment variables.
 * <p>
 * The configuration model is <strong>positive (enable-based)</strong> and layered:
 * <ol>
 *   <li><b>Per-chain override</b> {@code SIGNER_ENABLE_CHAIN_<CHAIN_NAME>} (final word):
 *       set to {@code true} to load a specific chain or {@code false} to skip it,
 *       regardless of the environment profile. {@code CHAIN_NAME} is the chain name in
 *       upper case with dashes replaced by underscores
 *       (e.g., {@code SIGNER_ENABLE_CHAIN_ICP_BRASIL_HOMOLOG}). The override works in both
 *       directions: it can enable a production chain while in a homologation profile, or
 *       enable a homologation chain while in a production profile.</li>
 *   <li><b>Environment profile</b> {@code SIGNER_ENV}:
 *       <ul>
 *         <li>{@code prod} / {@code production} (or unset): only production chains</li>
 *         <li>{@code hom} / {@code homolog}: only homologation chains</li>
 *         <li>{@code both} (alias {@code pro,hom} / {@code hom,pro}): production and
 *             homologation chains together</li>
 *       </ul></li>
 *   <li><b>Secure default</b> (nothing set): production chains loaded, homologation chains
 *       skipped.</li>
 * </ol>
 * <p>
 * <strong>Homologation chains are opt-in for security reasons.</strong> Homologation
 * certificates are issued by test authorities with weaker controls, so loading them by
 * default could allow a signature made with a homologation certificate to be accepted as
 * valid. Therefore they are only loaded when {@code SIGNER_ENV} selects them
 * ({@code hom} or {@code both}) or when explicitly enabled via
 * {@code SIGNER_ENABLE_CHAIN_<NAME>=true}.
 *
 * @since 4.6.3
 */
public final class DisablingUtil {

    private static final String ENABLE_ENV_PREFIX = "SIGNER_ENABLE_CHAIN_";
    private static final String ENV_VARIABLE = "SIGNER_ENV";

    private static final Logger LOGGER = LoggerFactory.getLogger(DisablingUtil.class);

    private DisablingUtil() {
        // Utility class - not instantiable
    }

    /**
     * Checks whether a chain should be skipped (not loaded).
     * <p>
     * The name is kept for backward source compatibility with the providers; a
     * {@code true} result means "do not load this chain".
     *
     * @param chainName the chain/module name (e.g., "icp-brasil-homolog", "iti-homolog")
     * @return true if the chain should be skipped, false if it should be loaded
     */
    public static boolean isChainDisabled(String chainName) {
        return isChainDisabled(chainName, System.getenv());
    }

    /**
     * Convenience inverse of {@link #isChainDisabled(String)}.
     *
     * @param chainName the chain/module name
     * @return true if the chain should be loaded
     */
    public static boolean isChainEnabled(String chainName) {
        return !isChainDisabled(chainName);
    }

    /**
     * Checks whether a chain should be skipped, based on the given environment map.
     *
     * @param chainName the chain/module name
     * @param env       the environment variables map
     * @return true if the chain should be skipped, false if it should be loaded
     */
    static boolean isChainDisabled(String chainName, Map<String, String> env) {
        // 1. Per-chain override has the final word (both directions).
        String variableName = toEnableVariableName(chainName);
        String variableValue = env.get(variableName);
        if (variableValue != null && !variableValue.trim().isEmpty()) {
            boolean enabled = Boolean.parseBoolean(variableValue.trim());
            LOGGER.info("Chain '{}' {} via {}={}", chainName, enabled ? "enabled" : "disabled",
                    variableName, variableValue.trim());
            return !enabled;
        }

        // 2. Environment profile.
        return !isChainEnabledByEnv(chainName, getEnvironment(env));
    }

    /**
     * Decides whether a chain is enabled by the {@code SIGNER_ENV} profile, applying the
     * secure default (homologation chains are opt-in).
     *
     * @param chainName the chain/module name
     * @param envValue  the raw value of {@code SIGNER_ENV}
     * @return true if the chain should be loaded under the given profile
     */
    private static boolean isChainEnabledByEnv(String chainName, String envValue) {
        boolean isHomologChain = chainName.toLowerCase().contains("homolog");

        boolean profileWantsProduction = isProductionProfile(envValue) || isBothProfile(envValue) || envValue.isEmpty();
        boolean profileWantsHomologation = isHomologationProfile(envValue) || isBothProfile(envValue);

        boolean enabled = isHomologChain ? profileWantsHomologation : profileWantsProduction;

        if (!enabled && isHomologChain) {
            LOGGER.info("Homologation chain '{}' not loaded (opt-in). To load it set {}=hom, {}=both, or {}=true.",
                    chainName, ENV_VARIABLE, ENV_VARIABLE, toEnableVariableName(chainName));
        } else if (!enabled) {
            LOGGER.info("Production chain '{}' not loaded because {}={} selects homologation only. "
                    + "To load it set {}=true.", chainName, ENV_VARIABLE, envValue, toEnableVariableName(chainName));
        }
        return enabled;
    }

    private static boolean isProductionProfile(String envValue) {
        return "prod".equalsIgnoreCase(envValue) || "production".equalsIgnoreCase(envValue)
                || "pro".equalsIgnoreCase(envValue);
    }

    private static boolean isHomologationProfile(String envValue) {
        return "hom".equalsIgnoreCase(envValue) || "homolog".equalsIgnoreCase(envValue);
    }

    /**
     * Whether the profile selects both production and homologation.
     * Accepts {@code both} and the comma list aliases {@code pro,hom} / {@code hom,pro}
     * (spaces tolerated).
     */
    private static boolean isBothProfile(String envValue) {
        if ("both".equalsIgnoreCase(envValue)) {
            return true;
        }
        String normalized = envValue.replace(" ", "").toLowerCase();
        return "pro,hom".equals(normalized) || "hom,pro".equals(normalized)
                || "prod,hom".equals(normalized) || "hom,prod".equals(normalized);
    }

    /**
     * Gets the environment profile from the {@code SIGNER_ENV} environment variable.
     *
     * @return the environment value (empty string if not set)
     */
    public static String getEnvironment() {
        return getEnvironment(System.getenv());
    }

    /**
     * Gets the environment profile from the given environment variables map.
     *
     * @param env the environment variables map
     * @return the environment value (empty string if not set)
     */
    static String getEnvironment(Map<String, String> env) {
        String value = env.get(ENV_VARIABLE);
        return value == null ? "" : value.trim();
    }

    /**
     * Converts a chain name to its per-chain enable environment variable name.
     * Example: "icp-brasil-homolog" becomes "SIGNER_ENABLE_CHAIN_ICP_BRASIL_HOMOLOG".
     *
     * @param chainName the chain/module name
     * @return the corresponding environment variable name
     */
    static String toEnableVariableName(String chainName) {
        return ENABLE_ENV_PREFIX + chainName.toUpperCase().replace('-', '_');
    }
}
