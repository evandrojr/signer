/*
 * Demoiselle Framework
 * Copyright (C) 2026 SERPRO
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

package org.demoiselle.signer.core.keystore.loader.implementation;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Provider;
import java.security.Security;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Helper class to create PKCS#11 providers with compatibility for both
 * Java 8 (using reflection with sun.security.pkcs11.SunPKCS11) and
 * Java 9+ (using Provider.configure() API).
 * 
 * This class detects the Java version at runtime and uses the appropriate
 * method to configure PKCS#11 providers.
 * 
 * @author Evandro Magalhães Leite Júnior
 * @since 4.6.0
 */
public class PKCS11ProviderHelper {

	private static final Logger logger = LoggerFactory.getLogger(PKCS11ProviderHelper.class);
	private static final int JAVA_VERSION = getJavaVersion();
	
	/**
	 * Creates a PKCS#11 provider using the provided configuration string.
	 * 
	 * The configuration string should be in the format:
	 * <pre>
	 * name = ProviderName
	 * library = /path/to/pkcs11/library.so
	 * </pre>
	 * 
	 * @param config PKCS#11 configuration string
	 * @return Configured Provider instance
	 * @throws Exception if provider creation fails
	 */
	public static Provider createProvider(String config) throws Exception {
		logger.debug("Creating PKCS#11 provider with Java version: {}", JAVA_VERSION);
		
		if (JAVA_VERSION >= 9) {
			return createProviderJava9Plus(config);
		} else {
			return createProviderJava8(config);
		}
	}
	
	/**
	 * Creates a PKCS#11 provider from a configuration file path.
	 * 
	 * @param configFilePath Path to PKCS#11 configuration file
	 * @return Configured Provider instance
	 * @throws Exception if provider creation fails
	 */
	public static Provider createProviderFromFile(String configFilePath) throws Exception {
		logger.debug("Creating PKCS#11 provider from file: {}", configFilePath);
		
		if (JAVA_VERSION >= 9) {
			return createProviderJava9PlusFromFile(configFilePath);
		} else {
			return createProviderJava8FromFile(configFilePath);
		}
	}
	
	/**
	 * Performs login on a PKCS#11 provider.
	 * 
	 * In Java 8, this calls the provider's login() method.
	 * In Java 9+, login is handled automatically by KeyStore.Builder.
	 * 
	 * @param provider PKCS#11 provider
	 * @param subject Subject (usually null)
	 * @param callbackHandler Callback handler for PIN
	 * @throws Exception if login fails
	 */
	public static void login(Provider provider, Subject subject, CallbackHandler callbackHandler) throws Exception {
		if (JAVA_VERSION >= 9) {
			// In Java 9+, login is handled automatically by KeyStore.Builder
			logger.debug("Java 9+ detected: login will be handled automatically");
		} else {
			loginJava8(provider, subject, callbackHandler);
		}
	}
	
	/**
	 * Performs logout on a PKCS#11 provider.
	 * 
	 * In Java 8, calls the provider's logout() method.
	 * In Java 9+, simply removes the provider.
	 * 
	 * @param provider PKCS#11 provider
	 * @return true if logout was successful
	 */
	public static boolean logout(Provider provider) {
		try {
			if (JAVA_VERSION >= 9) {
				return logoutJava9Plus(provider);
			} else {
				return logoutJava8(provider);
			}
		} catch (Exception e) {
			logger.error("Error during logout: {}", e.getMessage());
			return false;
		}
	}
	
	/**
	 * Creates provider using Java 8 reflection API (sun.security.pkcs11.SunPKCS11).
	 */
	@SuppressWarnings("restriction")
	private static Provider createProviderJava8(String config) throws Exception {
		logger.debug("Using Java 8 SunPKCS11 API");
		
		Constructor<?> constructor = Class.forName("sun.security.pkcs11.SunPKCS11")
			.getConstructor(InputStream.class);
		
		ByteArrayInputStream configStream = new ByteArrayInputStream(config.getBytes());
		Provider provider = (Provider) constructor.newInstance(configStream);
		configStream.close();
		
		return provider;
	}
	
	/**
	 * Creates provider using Java 8 reflection API with config file.
	 */
	@SuppressWarnings("restriction")
	private static Provider createProviderJava8FromFile(String configFilePath) throws Exception {
		logger.debug("Using Java 8 SunPKCS11 API with config file");
		
		Constructor<?> constructor = Class.forName("sun.security.pkcs11.SunPKCS11")
			.getConstructor(String.class);
		
		Provider provider = (Provider) constructor.newInstance(configFilePath);
		
		return provider;
	}
	
	/**
	 * Creates provider using Java 9+ Provider.configure() API.
	 */
	private static Provider createProviderJava9Plus(String config) throws Exception {
		logger.debug("Using Java 9+ Provider.configure() API");
		
		// Create temporary configuration file
		Path configFile = Files.createTempFile("pkcs11-", ".cfg");
		
		try {
			Files.write(configFile, config.getBytes());
			
			// Get SunPKCS11 provider template
			Provider template = Security.getProvider("SunPKCS11");
			if (template == null) {
				throw new IllegalStateException("SunPKCS11 provider not available");
			}
			
			// Configure provider with the config file
			Provider provider = template.configure(configFile.toString());
			
			return provider;
			
		} finally {
			// Clean up temporary file
			try {
				Files.deleteIfExists(configFile);
			} catch (IOException e) {
				logger.warn("Failed to delete temporary config file: {}", e.getMessage());
			}
		}
	}
	
	/**
	 * Creates provider using Java 9+ Provider.configure() API with existing config file.
	 */
	private static Provider createProviderJava9PlusFromFile(String configFilePath) throws Exception {
		logger.debug("Using Java 9+ Provider.configure() API with config file");
		
		// Get SunPKCS11 provider template
		Provider template = Security.getProvider("SunPKCS11");
		if (template == null) {
			throw new IllegalStateException("SunPKCS11 provider not available");
		}
		
		// Configure provider with the config file
		Provider provider = template.configure(configFilePath);
		
		return provider;
	}
	
	/**
	 * Performs login using Java 8 reflection API.
	 */
	@SuppressWarnings("restriction")
	private static void loginJava8(Provider provider, Subject subject, CallbackHandler callbackHandler) throws Exception {
		logger.debug("Performing Java 8 login");
		
		Method loginMethod = Class.forName("sun.security.pkcs11.SunPKCS11")
			.getMethod("login", Subject.class, CallbackHandler.class);
		
		loginMethod.invoke(provider, subject, callbackHandler);
	}
	
	/**
	 * Performs logout using Java 8 reflection API.
	 */
	@SuppressWarnings("restriction")
	private static boolean logoutJava8(Provider provider) throws Exception {
		logger.debug("Performing Java 8 logout");
		
		Method logoutMethod = Class.forName("sun.security.pkcs11.SunPKCS11")
			.getMethod("logout");
		
		logoutMethod.invoke(provider);
		return true;
	}
	
	/**
	 * Performs logout for Java 9+ by removing the provider.
	 */
	private static boolean logoutJava9Plus(Provider provider) {
		logger.debug("Performing Java 9+ logout (removing provider)");
		
		Security.removeProvider(provider.getName());
		return true;
	}
	
	/**
	 * Detects the major Java version.
	 * 
	 * @return Java major version (7, 8, 9, 11, 17, 21, etc.)
	 */
	private static int getJavaVersion() {
		String version = System.getProperty("java.version");
		
		// Java 8 and earlier: "1.8.0_xxx"
		if (version.startsWith("1.")) {
			return Integer.parseInt(version.substring(2, 3));
		}
		
		// Java 9+: "9.0.1", "11.0.1", "21.0.1", etc.
		int dotIndex = version.indexOf('.');
		if (dotIndex != -1) {
			return Integer.parseInt(version.substring(0, dotIndex));
		}
		
		// Fallback
		return Integer.parseInt(version);
	}
	
	/**
	 * Returns the detected Java version.
	 * 
	 * @return Java major version number
	 */
	public static int getDetectedJavaVersion() {
		return JAVA_VERSION;
	}
}
