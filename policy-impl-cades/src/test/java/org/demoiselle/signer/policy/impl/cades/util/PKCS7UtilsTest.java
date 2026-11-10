package org.demoiselle.signer.policy.impl.cades.util;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;

import java.util.Arrays;

import org.junit.Test;

/**
 * Testes de {@link PKCS7Utils#removerPreenchimento(byte[])}.
 */
public class PKCS7UtilsTest {

	/** SEQUENCE { INTEGER 1, OCTET STRING 'AB' } em DER. */
	private static final byte[] DER = { 0x30, 0x07, 0x02, 0x01, 0x01, 0x04, 0x02, 0x41, 0x42 };

	/** Mesma estrutura com comprimento indefinido (BER), terminada por 00 00. */
	private static final byte[] BER = { 0x30, (byte) 0x80, 0x02, 0x01, 0x01, 0x04, 0x02, 0x41, 0x42, 0x00, 0x00 };

	private static byte[] comZeros(byte[] base, int zeros) {
		return Arrays.copyOf(base, base.length + zeros);
	}

	@Test
	public void semPreenchimento_devolveOriginal() {
		assertSame(DER, PKCS7Utils.removerPreenchimento(DER));
	}

	@Test
	public void der_comZeros_removePreenchimento() {
		assertArrayEquals(DER, PKCS7Utils.removerPreenchimento(comZeros(DER, 100)));
	}

	@Test
	public void ber_comZeros_preservaMarcadorDeFim() {
		assertArrayEquals(BER, PKCS7Utils.removerPreenchimento(comZeros(BER, 50)));
	}

	@Test
	public void ber_semPreenchimento_devolveOriginal() {
		assertSame(BER, PKCS7Utils.removerPreenchimento(BER));
	}

	@Test
	public void comprimentoLongo_comZeros_removePreenchimento() {
		// OCTET STRING de 200 bytes, comprimento em forma longa (81 C8)
		byte[] obj = new byte[3 + 200];
		obj[0] = 0x04;
		obj[1] = (byte) 0x81;
		obj[2] = (byte) 200;
		Arrays.fill(obj, 3, obj.length, (byte) 0x55);
		assertArrayEquals(obj, PKCS7Utils.removerPreenchimento(comZeros(obj, 1000)));
	}

	@Test
	public void excedenteNaoZero_devolveOriginal() {
		byte[] lixo = comZeros(DER, 3);
		lixo[lixo.length - 1] = 0x01;
		assertSame(lixo, PKCS7Utils.removerPreenchimento(lixo));
	}

	@Test
	public void truncado_devolveOriginal() {
		byte[] truncado = Arrays.copyOf(DER, 5);
		assertSame(truncado, PKCS7Utils.removerPreenchimento(truncado));
	}

	@Test
	public void nuloOuCurto_devolveOriginal() {
		assertNull(PKCS7Utils.removerPreenchimento(null));
		byte[] um = { 0x30 };
		assertSame(um, PKCS7Utils.removerPreenchimento(um));
	}
}
