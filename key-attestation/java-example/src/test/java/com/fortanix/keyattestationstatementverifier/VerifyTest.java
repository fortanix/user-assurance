package com.fortanix.keyattestationstatementverifier;

import org.junit.Ignore;
import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fortanix.keyattestationstatementverifier.types.json.KeyAttestationResponse;

import static org.junit.Assert.*;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.UUID;

import javax.net.ssl.HttpsURLConnection;

public class VerifyTest {
    private static final String FORTANIX_AMER_SAAS_SERVER_URL = "https://amer.smartkey.io";
    private static final String JAVA_CI_AMER_APP_API_KEY = "AMER_APP_API_KEY";
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
        // because at time this code is written, CRL server is not setup, we turn of the
        // CRL check
        Verify.verify(authorityChain, cert_chain.get(0), trusted, false);
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
        // because at time this code is written, CRL server is not setup, we turn of the
        // CRL check
        Verify.verify(decodedResponse, trusted, false);
    }

    /**
     * This test is ignored because it's an example code for showing how to verify a
     * real 'Fortanix DSM Key Attestation'
     *
     * @throws Exception
     */
    @Ignore
    @Test
    public void verifyStatementFullCheckExample() throws Exception {
        String jsonPath = "Path to the KeyAttestationResponse json file";
        Reader reader = new FileReader(jsonPath);
        ObjectMapper objectMapper = new ObjectMapper();
        KeyAttestationResponse decodedResponse = objectMapper.readValue(reader, KeyAttestationResponse.class);

        System.out.println("Downloading Fortanix Attestation and Provisioning Root CA certificate form: "
                + Common.FORTANIX_ATTESTATION_AND_PROVISIONING_ROOT_CA_CERT_URL);
        X509Certificate trustedRootCert = Common.getFortanixRootCaCertRemote(
                Common.FORTANIX_ATTESTATION_AND_PROVISIONING_ROOT_CA_CERT_URL);

        Verify.verify(decodedResponse, trustedRootCert, true);
    }

    /**
     * This test tests the full process of creating a RSA key, get RSA key's key
     * attestation statement and finally verify it.
     *
     * @throws Exception
     */
    @Test
    public void verifyStatementFullCheckOnlineAMER() throws Exception {
        // Because here we use an APP API key so we could skip many steps: select an account / create a group
        String appApiKeyString = System.getenv(JAVA_CI_AMER_APP_API_KEY);
        String authString = "Basic " + appApiKeyString;
        // Create a RSA key
        String generateKeyUrl = FORTANIX_AMER_SAAS_SERVER_URL + "/crypto/v1/keys";
        String newRsaKeyName = UUID.randomUUID().toString();
        String generateKeyRequest = String.format(
                "{\"name\":\"%s\",\"description\":\"\",\"obj_type\":\"RSA\",\"key_ops\":[\"APPMANAGEABLE\",\"SIGN\",\"VERIFY\"],\"key_size\":2048,\"pub_exponent\":65537,\"expirationDate\":null,\"enabled\":true,\"rsa\":{\"encryption_policy\":[{\"padding\":{\"OAEP\":{\"mgf\":{\"mgf1\":{}}}}}],\"signature_policy\":[{\"padding\":{\"PKCS1_V15\":{}}},{\"padding\":{\"PSS\":{\"mgf\":{\"mgf1\":{}}}}}]}}",
                newRsaKeyName);
        System.out.println(
                String.format("Creating a new RSA key named '%s' through %s ...", newRsaKeyName, generateKeyUrl));
        String generateKeyResponseString = sendHttpRequest(generateKeyUrl, "POST", generateKeyRequest, authString);
        ObjectMapper keyObjectMapper = new ObjectMapper();
        JsonNode jsonNode = keyObjectMapper.readTree(generateKeyResponseString);
        String keyId = jsonNode.get("kid").asText();
        System.out.println(String.format("Created a new RSA key named '%s' with key id: %s", newRsaKeyName, keyId));

        String getKeyAttestationUrl = FORTANIX_AMER_SAAS_SERVER_URL + "/crypto/v1/keys/key_attestation";
        String getKeyAttestationRequest = String.format("{\"key\":{\"kid\":\"%s\"}}", keyId);
        System.out.println(String.format("Getting key attestation statement through %s ...", getKeyAttestationUrl));
        String keyAttestationResponseString = sendHttpRequest(getKeyAttestationUrl, "POST", getKeyAttestationRequest, authString);
        System.out.println(String.format("Got key attestation statement"));

        // Get the the key attestation statement of the key just created
        ObjectMapper attestationObjectMapper = new ObjectMapper();
        KeyAttestationResponse decodedResponse = attestationObjectMapper.readValue(keyAttestationResponseString, KeyAttestationResponse.class);

        System.out.println("Downloading Fortanix Attestation and Provisioning Root CA certificate form: "
                + Common.FORTANIX_ATTESTATION_AND_PROVISIONING_ROOT_CA_CERT_URL);
        X509Certificate trustedRootCert = Common.getFortanixRootCaCertRemote(
                Common.FORTANIX_ATTESTATION_AND_PROVISIONING_ROOT_CA_CERT_URL);
        System.out.println(String.format("Downloaded Fortanix Attestation and Provisioning Root CA"));

        Verify.verify(decodedResponse, trustedRootCert, true);
    }

    public static String sendHttpRequest(String url, String method, String body, String authorization)
            throws IOException {
        URL apiUrl = new URL(url);
        HttpsURLConnection connection = (HttpsURLConnection) apiUrl.openConnection();

        try {
            // Set the HTTP method
            connection.setRequestMethod(method);

            // Set the Authorization header if provided
            if (authorization != null && !authorization.isEmpty()) {
                connection.setRequestProperty("Authorization", authorization);
            }

            // Handle request body if provided
            if (body != null && !body.isEmpty()) {
                connection.setDoOutput(true);
                connection.getOutputStream().write(body.getBytes("UTF-8"));
            }

            int responseCode = connection.getResponseCode();
            if (responseCode >= 200 && responseCode < 300) {
                // Successful response, read and return the response body
                BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                StringBuilder response = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }
                reader.close();
                return response.toString();
            } else {
                // Non-2XX response, throw an exception
                throw new IOException("HTTP request failed with response code: " + responseCode);
            }
        } finally {
            connection.disconnect();
        }
    }
}
