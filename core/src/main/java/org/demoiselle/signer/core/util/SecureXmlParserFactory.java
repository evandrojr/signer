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

import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

/**
 * Cria {@link DocumentBuilderFactory} protegida contra XXE (XML External Entity).
 *
 * <p>Sem estas configuracoes o parser resolve DTDs e entidades externas declaradas
 * no documento, o que permite ler arquivos locais e disparar requisicoes HTTP
 * arbitrarias (SSRF) a partir de um XML recebido de terceiros.
 *
 * <p>A protecao principal e {@code disallow-doctype-decl}: recusa qualquer documento
 * que contenha {@code <!DOCTYPE>}. Como toda entidade externa e declarada dentro do
 * DOCTYPE, uma unica flag bloqueia leitura de arquivo, SSRF e expansao de entidades
 * em massa. Formatos de assinatura (XAdES, XMLDSig) exigem documento sem DTD, portanto
 * nada legitimo e perdido.
 */
public final class SecureXmlParserFactory {

	private static final Logger LOGGER = Logger.getLogger(SecureXmlParserFactory.class.getName());

	private SecureXmlParserFactory() {
		// classe utilitaria
	}

	/**
	 * Cria uma factory ja endurecida contra XXE.
	 *
	 * @return a factory configurada.
	 * @throws ParserConfigurationException se o parser nao suportar a protecao principal.
	 */
	public static DocumentBuilderFactory newDocumentBuilderFactory() throws ParserConfigurationException {
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		harden(factory);
		return factory;
	}

	/**
	 * Aplica as protecoes contra XXE em uma factory existente.
	 *
	 * <p>A flag {@code disallow-doctype-decl} e obrigatoria: se o parser nao a
	 * suportar, a excecao e propagada para que a operacao falhe em vez de seguir
	 * com o parser desprotegido. As demais flags sao complementares e, quando nao
	 * suportadas, apenas registram aviso.
	 *
	 * @param factory a factory a proteger.
	 * @throws ParserConfigurationException se a protecao principal nao puder ser aplicada.
	 */
	public static void harden(DocumentBuilderFactory factory) throws ParserConfigurationException {
		// Obrigatoria: sem isto o parser aceita DTD e entidades externas.
		factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

		// Complementares: reforcam a mesma protecao em parsers que nao exponham a flag acima.
		tryFeature(factory, XMLConstants.FEATURE_SECURE_PROCESSING, true);
		tryFeature(factory, "http://xml.org/sax/features/external-general-entities", false);
		tryFeature(factory, "http://xml.org/sax/features/external-parameter-entities", false);
		tryFeature(factory, "http://apache.org/xml/features/nonvalidating/load-external-dtd", false);

		try {
			factory.setXIncludeAware(false);
		} catch (UnsupportedOperationException e) {
			LOGGER.log(Level.FINE, "setXIncludeAware nao suportado pelo parser", e);
		}
		factory.setExpandEntityReferences(false);
	}

	private static void tryFeature(DocumentBuilderFactory factory, String feature, boolean value) {
		try {
			factory.setFeature(feature, value);
		} catch (ParserConfigurationException | IllegalArgumentException e) {
			LOGGER.log(Level.FINE, "feature nao suportada: " + feature, e);
		}
	}
}
