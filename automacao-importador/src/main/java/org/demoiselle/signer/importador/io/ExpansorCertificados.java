package org.demoiselle.signer.importador.io;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Expande bundles de certificados ICP-Brasil para {@link X509Certificate}, sem
 * recorrer a subprocessos externos ({@code openssl}/{@code keytool}).
 *
 * <p>Substitui integralmente o uso de {@code openssl}:</p>
 * <ul>
 *   <li>O ZIP de produção ({@code ACcompactadox.zip}) é expandido via
 *       {@link java.util.zip.ZipInputStream}; cada entrada {@code .crt}/{@code .cer}
 *       é parseada como {@link X509Certificate} através de
 *       {@code CertificateFactory} para {@code "X.509"} no provider BouncyCastle,
 *       que aceita parâmetros de curva EC explícitos (rejeitados pelo provider Sun).</li>
 *   <li>Arquivos {@code .p7b} (PKCS#7 / CMS) são expandidos via
 *       {@link org.bouncycastle.cms.CMSSignedData}, convertendo cada
 *       {@link X509CertificateHolder} contido em {@link X509Certificate} através de
 *       {@link JcaX509CertificateConverter} com o provider BouncyCastle.</li>
 * </ul>
 *
 * <p>Não aplica nenhum filtro por validade: todos os certificados encontrados são
 * retornados. Falhas de parsing são propagadas como {@link ExpansaoException}
 * (runtime), identificando a origem.</p>
 *
 * <p>Requirements: 2.1.</p>
 */
public final class ExpansorCertificados {

	private static final String PROVIDER_BC = "BC";

	static {
		// Garante o provider BC disponível para o converter, mesmo que o Main
		// ainda não o tenha registrado (idempotente).
		if (java.security.Security.getProvider(PROVIDER_BC) == null) {
			java.security.Security.addProvider(new BouncyCastleProvider());
		}
	}

	/**
	 * Expande o conteúdo de um ZIP de produção, extraindo os certificados das
	 * entradas com extensão {@code .crt} ou {@code .cer}.
	 *
	 * <p>Entradas de diretório e entradas cuja extensão não seja de certificado são
	 * ignoradas. Cada entrada de certificado é parseada como DER ou PEM via
	 * {@code CertificateFactory("X.509")}.</p>
	 *
	 * @param zipBytes os bytes do arquivo ZIP (não nulo)
	 * @return a lista de certificados extraídos, na ordem de leitura do ZIP
	 * @throws ExpansaoException se o ZIP não puder ser lido ou uma entrada de
	 *                           certificado não puder ser parseada
	 */
	public List<X509Certificate> expandirZip(byte[] zipBytes) {
		Objects.requireNonNull(zipBytes, "zipBytes");
		List<X509Certificate> certificados = new ArrayList<>();
		try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(zipBytes))) {
			ZipEntry entrada;
			while ((entrada = zis.getNextEntry()) != null) {
				if (entrada.isDirectory() || !ehCertificado(entrada.getName())) {
					zis.closeEntry();
					continue;
				}
				byte[] bytes = lerEntrada(zis);
				zis.closeEntry();
				certificados.add(parsearCertificado(bytes, entrada.getName()));
			}
		} catch (IOException e) {
			throw new ExpansaoException("Falha ao ler o ZIP de certificados", e);
		}
		return certificados;
	}

	/**
	 * Expande um arquivo {@code .p7b} (PKCS#7 / CMS), retornando todos os
	 * {@link X509Certificate} nele contidos.
	 *
	 * <p>Tenta primeiro interpretar os bytes como CMS/DER; se isso falhar, decodifica
	 * todos os blocos PEM encontrados (suportando arquivos anotados com linhas
	 * {@code subject}/{@code issuer} entre certificados) e, para cada bloco, tenta
	 * interpretá-lo como CMS e, em seguida, como um certificado X.509 avulso.</p>
	 *
	 * @param p7bBytes os bytes do arquivo {@code .p7b} (DER ou PEM; não nulo)
	 * @return a lista de certificados contidos no PKCS#7
	 * @throws ExpansaoException se o conteúdo não puder ser interpretado como PKCS#7
	 */
	public List<X509Certificate> expandirP7b(byte[] p7bBytes) {
		Objects.requireNonNull(p7bBytes, "p7bBytes");
		try {
			return converterP7b(new CMSSignedData(p7bBytes));
		} catch (CMSException derFalhou) {
			// Fallback: decodifica todos os blocos PEM e tenta cada um como CMS ou
			// certificado avulso (arquivos .p7b reais podem conter certs PEM anotados).
			return expandirBlocosPem(p7bBytes, derFalhou);
		}
	}

	private List<X509Certificate> expandirBlocosPem(byte[] p7bBytes, CMSException derFalhou) {
		List<byte[]> blocos = decodificarBlocosPem(p7bBytes);
		if (blocos.isEmpty()) {
			throw new ExpansaoException("Conteúdo p7b inválido: não é PKCS#7 DER nem PEM", derFalhou);
		}
		List<X509Certificate> certificados = new ArrayList<>();
		for (int i = 0; i < blocos.size(); i++) {
			byte[] der = blocos.get(i);
			try {
				certificados.addAll(converterP7b(new CMSSignedData(der)));
			} catch (CMSException naoCms) {
				try {
					certificados.add(parsearCertificado(der, "bloco PEM " + (i + 1)));
				} catch (ExpansaoException naoCert) {
					// Bloco irreconhecível: ignora e segue para o próximo; se nenhum
					// bloco produzir certificado, a exceção original é lançada abaixo.
				}
			}
		}
		if (certificados.isEmpty()) {
			throw new ExpansaoException("Conteúdo p7b inválido após decodificação PEM", derFalhou);
		}
		return certificados;
	}

	/** Converte os certificados de um {@link CMSSignedData} (PKCS#7) para {@link X509Certificate}. */
	private static List<X509Certificate> converterP7b(CMSSignedData cms) {
		JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider(PROVIDER_BC);
		List<X509Certificate> certificados = new ArrayList<>();
		try {
			for (X509CertificateHolder holder : cms.getCertificates().getMatches(null)) {
				certificados.add(converter.getCertificate(holder));
			}
		} catch (CertificateException e) {
			throw new ExpansaoException("Falha ao converter certificado do PKCS#7", e);
		}
		return certificados;
	}

	/**
	 * Parseia um único certificado a partir de bytes em DER ou PEM, usando
	 * {@code CertificateFactory("X.509")}.
	 *
	 * @param bytes  os bytes do certificado (não nulo)
	 * @param origem identificador da origem, usado apenas em mensagens de erro
	 * @return o {@link X509Certificate} parseado
	 * @throws ExpansaoException se os bytes não representarem um certificado X.509
	 */
	public X509Certificate parsearCertificado(byte[] bytes, String origem) {
		Objects.requireNonNull(bytes, "bytes");
		try {
			CertificateFactory cf = CertificateFactory.getInstance("X.509", PROVIDER_BC);
			return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(bytes));
		} catch (CertificateException | java.security.NoSuchProviderException e) {
			throw new ExpansaoException("Falha ao parsear certificado X.509 de '" + origem + "'", e);
		}
	}

	private static boolean ehCertificado(String nome) {
		String lower = nome.toLowerCase(Locale.ROOT);
		return lower.endsWith(".crt") || lower.endsWith(".cer");
	}

	private static byte[] lerEntrada(InputStream in) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		byte[] buffer = new byte[8192];
		int lidos;
		while ((lidos = in.read(buffer)) != -1) {
			baos.write(buffer, 0, lidos);
		}
		return baos.toByteArray();
	}

	/**
	 * Decodifica todos os blocos PEM ({@code -----BEGIN ...-----} ... {@code -----END
	 * ...-----}) para os bytes DER correspondentes, ignorando qualquer texto entre
	 * blocos (ex.: anotações {@code subject}/{@code issuer} presentes em alguns
	 * arquivos {@code .p7b}). Retorna uma lista vazia se não houver blocos PEM.
	 */
	private static List<byte[]> decodificarBlocosPem(byte[] bytes) {
		String texto = new String(bytes, java.nio.charset.StandardCharsets.ISO_8859_1);
		List<byte[]> blocos = new ArrayList<>();
		int posicao = 0;
		while (true) {
			int inicio = texto.indexOf("-----BEGIN", posicao);
			if (inicio < 0) {
				break;
			}
			int fimCabecalho = texto.indexOf('\n', inicio);
			int fim = texto.indexOf("-----END", fimCabecalho < 0 ? inicio : fimCabecalho);
			if (fimCabecalho < 0 || fim < 0) {
				break;
			}
			String base64 = texto.substring(fimCabecalho + 1, fim).replaceAll("\\s", "");
			try {
				blocos.add(java.util.Base64.getDecoder().decode(base64));
			} catch (IllegalArgumentException ignorado) {
				// Bloco PEM corrompido: ignora e tenta o próximo.
			}
			posicao = fim + 9;
		}
		return blocos;
	}

	/**
	 * Exceção de runtime lançada quando um bundle de certificados não pode ser
	 * expandido (ZIP corrompido, PKCS#7 inválido ou certificado não parseável).
	 */
	public static final class ExpansaoException extends RuntimeException {

		private static final long serialVersionUID = 1L;

		public ExpansaoException(String mensagem, Throwable causa) {
			super(mensagem, causa);
		}
	}
}
