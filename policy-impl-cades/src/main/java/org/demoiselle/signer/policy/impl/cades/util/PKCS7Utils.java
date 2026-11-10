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

package org.demoiselle.signer.policy.impl.cades.util;

import java.util.Arrays;

/**
 * Utilitários para tratamento de pacotes PKCS#7/CMS em bytes brutos.
 *
 * <p>A partir da versão 1.85, o Bouncy Castle passou a rejeitar bytes
 * excedentes após o objeto ASN.1 ({@code IOException: Extra data detected in
 * stream}). Assinaturas extraídas do campo {@code /Contents} de PDFs (PAdES)
 * normalmente vêm com zeros de preenchimento após o PKCS#7, pois o espaço é
 * reservado antes da assinatura. Esses zeros não fazem parte da assinatura
 * (ficam fora do {@code /ByteRange}) e eram aceitos pelas versões anteriores.</p>
 */
public final class PKCS7Utils {

	private PKCS7Utils() {
		// utilitário
	}

	/**
	 * Remove os zeros de preenchimento após o fim do objeto ASN.1 externo.
	 *
	 * <p>Somente zeros ({@code 0x00}) são removidos. Se houver qualquer outro
	 * byte excedente, ou se a estrutura não puder ser interpretada, o array
	 * original é devolvido sem alteração, e o Bouncy Castle reporta o erro
	 * normalmente. Suporta comprimento definido (DER) e indefinido (BER).</p>
	 *
	 * @param dados pacote PKCS#7 possivelmente com preenchimento.
	 * @return o pacote sem o preenchimento, ou o próprio array original.
	 */
	public static byte[] removerPreenchimento(byte[] dados) {
		if (dados == null || dados.length < 2) {
			return dados;
		}
		int fim;
		try {
			fim = fimDoObjeto(dados, 0, 0);
		} catch (RuntimeException e) {
			return dados;
		}
		if (fim <= 0 || fim >= dados.length) {
			return dados;
		}
		for (int i = fim; i < dados.length; i++) {
			if (dados[i] != 0) {
				return dados;
			}
		}
		return Arrays.copyOf(dados, fim);
	}

	/** Profundidade máxima de aninhamento BER, para evitar recursão sem limite. */
	private static final int PROFUNDIDADE_MAXIMA = 64;

	/**
	 * Devolve a posição logo após o fim do TLV que começa em {@code inicio}.
	 * Lança {@link IllegalArgumentException} se a estrutura for inválida.
	 */
	private static int fimDoObjeto(byte[] d, int inicio, int profundidade) {
		if (profundidade > PROFUNDIDADE_MAXIMA) {
			throw new IllegalArgumentException("aninhamento excessivo");
		}
		int p = inicio;
		int tag = ler(d, p++);
		boolean construido = (tag & 0x20) != 0;
		if ((tag & 0x1F) == 0x1F) {
			// Tag de vários bytes: continua enquanto o bit 8 estiver ligado
			while ((ler(d, p++) & 0x80) != 0) {
				// avança
			}
		}
		int b = ler(d, p++);
		if (b == 0x80) {
			// Comprimento indefinido (BER): só vale para tipos construídos;
			// percorre os filhos até o marcador de fim (00 00).
			if (!construido) {
				throw new IllegalArgumentException("comprimento indefinido em tipo primitivo");
			}
			while (true) {
				if (ler(d, p) == 0 && ler(d, p + 1) == 0) {
					return p + 2;
				}
				p = fimDoObjeto(d, p, profundidade + 1);
			}
		}
		long comprimento;
		if ((b & 0x80) == 0) {
			comprimento = b;
		} else {
			int n = b & 0x7F;
			if (n == 0 || n > 4) {
				throw new IllegalArgumentException("comprimento inválido");
			}
			comprimento = 0;
			for (int i = 0; i < n; i++) {
				comprimento = (comprimento << 8) | ler(d, p++);
			}
		}
		long fim = p + comprimento;
		if (fim > d.length) {
			throw new IllegalArgumentException("comprimento além do fim dos dados");
		}
		return (int) fim;
	}

	private static int ler(byte[] d, int i) {
		if (i < 0 || i >= d.length) {
			throw new IllegalArgumentException("fim inesperado dos dados");
		}
		return d[i] & 0xFF;
	}
}
