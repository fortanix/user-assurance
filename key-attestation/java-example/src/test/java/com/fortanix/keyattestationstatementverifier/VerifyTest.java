package com.fortanix.keyattestationstatementverifier;

import org.junit.Test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fortanix.keyattestationstatementverifier.types.json.KeyAttestationResponse;

import static org.junit.Assert.*;

import java.io.FileReader;
import java.io.Reader;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.List;

public class VerifyTest {
    private static final String VALID_STATEMENT_CERT_PEM = "key-attestation-statement.pem";
    private static final String VALID_RESPONSE_JSON = "key-attestation-response.json";

    private URL getTestFileUrl(String fileName) throws Exception {
        URL resUrl = getClass().getClassLoader().getResource(fileName);
        if (resUrl == null) {
            throw new IllegalArgumentException("Test resource file not found!");
        } else {
            return resUrl;
        }
    }

    /**
     * This test tests the verification logic expect CRL verification and Root CA
     * download, reading test data from a PEM file
     *
     * @throws Exception
     */
    @Test
    public void verifyStatementFromPemWithoutCrlCheck() throws Exception {
        // Note, the certificate in the file is in order of:
        // 1. Fortanix DSM Key Attestation
        // 2. Fortanix DSM SaaS Key Attestation Authority
        // 3. Fortanix Key Attestation CA
        // 4. Fortanix Attestation and Provisioning Root CA
        URL url = getTestFileUrl(VALID_STATEMENT_CERT_PEM);
        List<X509Certificate> cert_chain = Verify.readPemCertsFromPath(url.getPath());
        assertEquals(4, cert_chain.size());
        List<X509Certificate> authorityChain = cert_chain.subList(1, cert_chain.size());
        // Last certificate of Authority Chain is Root CA cert, since the test
        // certificate is using a fake root CA, so we assume root ca cert is correct by
        // using last certificate as trust CA certificate.
        // NOTE: please replace with Root CA certificate if you already downloaded it
        // somewhere.
        X509Certificate trusted = cert_chain.get(cert_chain.size() - 1);
        
        String fakeTimeEnv = System.getenv("FAKE_TIME_ACTIVE");
        if (fakeTimeEnv != null && "1".equals(fakeTimeEnv)) {
            Verify.verify(authorityChain, cert_chain.get(0), trusted, false);
        } else {
            Exception exception = assertThrows(Exception.class,
                    () -> Verify.verify(authorityChain, cert_chain.get(0), trusted, false));
            assertTrue("certificates should already expired, exception: " + exception.toString(),
                    exception.toString().contains("certificate expired") || exception.toString().contains("NotAfter"));
        }
    }

    /**
     * This test tests the verification logic expect CRL verification and Root CA
     * downloading, reading test data from a Json file storing a
     * KeyAttestationResponse
     *
     * @throws Exception
     */
    @Test
    public void verifyStatementFromJsonWithoutCrlCheck() throws Exception {
        URL url = getTestFileUrl(VALID_RESPONSE_JSON);
        Reader reader = new FileReader(url.getPath());
        ObjectMapper objectMapper = new ObjectMapper();
        KeyAttestationResponse decodedResponse = objectMapper.readValue(reader, KeyAttestationResponse.class);
        // Last certificate of Authority Chain is Root CA cert, since the test
        // certificate is using a fake root CA, so we assume root ca cert is correct by
        // using last certificate as trust CA certificate.
        // NOTE: please replace with Root CA certificate if you already downloaded it
        // somewhere.
        List<String> authorityChain = decodedResponse.getAuthorityChain();
        X509Certificate trusted = Verify.readBase64EncodedCertificate(authorityChain.get(authorityChain.size() - 1));

        String fakeTimeEnv = System.getenv("FAKE_TIME_ACTIVE");
        if (fakeTimeEnv != null && "1".equals(fakeTimeEnv)) {
            Verify.verify(decodedResponse, trusted, false);
        } else {
            Exception exception = assertThrows(Exception.class,
                    () -> Verify.verify(decodedResponse, trusted, false));
            assertTrue("certificates should already expired, exception: " + exception.toString(),
                    exception.toString().contains("certificate expired") || exception.toString().contains("NotAfter"));
        }
    }
}
