package org.demoiselle.signer.chain.icp.brasil.provider.hom;

import java.security.cert.X509Certificate;
import java.util.Collection;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

/**
 * Tests the HomologacaoProviderCA.
 * <p>
 * Since 4.6.3, homologation chains are <strong>opt-in</strong> for security reasons:
 * they are disabled by default and only loaded when explicitly enabled via
 * {@code SIGNER_ENV=hom} (or {@code both}) or {@code SIGNER_ENABLE_CHAIN_ICP_BRASIL_HOMOLOG=true}.
 * <p>
 * These tests run without those opt-in variables set, so the provider must return an
 * empty (but non-null) collection, confirming homologation certificates are not trusted
 * by default.
 */
class HomologacaoProviderCATest {

    @Test
    void testHomologationDisabledByDefault_returnsEmpty() {
        HomologacaoProviderCA provider = new HomologacaoProviderCA();
        Collection<X509Certificate> cas = provider.getCAs();
        assertNotNull(cas, "Coleção de CAs não pode ser nula");
        assertTrue(cas.isEmpty(),
                "Cadeia de homologação deve ser opt-in: sem habilitação explícita, "
                        + "nenhum certificado deve ser carregado");
    }
}
