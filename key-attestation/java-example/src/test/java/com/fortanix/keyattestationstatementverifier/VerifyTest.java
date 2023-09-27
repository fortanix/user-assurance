package com.fortanix.keyattestationstatementverifier;

import org.junit.Test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fortanix.keyattestationstatementverifier.types.json.KeyAttestationResponse;

import com.fortanix.sdkms.v1.ApiClient;
import com.fortanix.sdkms.v1.ApiException;
import com.fortanix.sdkms.v1.Configuration;
import com.fortanix.sdkms.v1.Pair;
import com.fortanix.sdkms.v1.api.AuthenticationApi;
import com.fortanix.sdkms.v1.api.SecurityObjectsApi;
import com.fortanix.sdkms.v1.auth.ApiKeyAuth;
import com.fortanix.sdkms.v1.model.AuthResponse;
import com.fortanix.sdkms.v1.model.KeyObject;
import com.fortanix.sdkms.v1.model.ObjectType;

import com.fortanix.sdkms.v1.model.SobjectRequest;

import static org.junit.Assert.*;

import java.io.FileReader;
import java.io.Reader;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.ws.rs.core.GenericType;

public class VerifyTest {
    private static final String FORTANIX_AMER_SAAS_SERVER_URL = "https://amer.smartkey.io";
    private static final String JAVA_CI_AMER_APP_API_KEY = "AMER_APP_API_KEY";
    private static final String VALID_STATEMENT_CERT_PEM = "key-attestation-statement.pem";
    private static final String VALID_RESPONSE_JSON = "key-attestation-response.json";
    private static final boolean DEBUG = false;

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
     * This test tests the full process:
     * 1. Creating a RSA key.
     * 2. Get RSA key's key attestation statement.
     * 3. Verify key attestation statement.
     *
     * @throws Exception
     */
    @Test
    public void verifyStatementFullCheckOnlineAMER() throws Exception {
        // Setup a SDKMS API client
        String appApiKeyString = System.getenv(JAVA_CI_AMER_APP_API_KEY);
        ApiClient client = new ApiClient();

        // Set the path of the server to talk to.
        client.setBasePath(FORTANIX_AMER_SAAS_SERVER_URL);

        // This optionally enables verbose logging in the API library.
        client.setDebugging(DEBUG);

        // The default ApiClient (and its configured authorization) will be
        // used for constructing the specific API objects, such as
        // AuthenticationApi and SecurityObjectsApi.
        Configuration.setDefaultApiClient(client);

        // When authenticating as an application, the API Key functions as
        // the entire HTTP basic auth token.
        client.setBasicAuthString(appApiKeyString);

        String bearerToken = null;
        // Acquire a bearer token to use for other APIs.
        try {
            AuthResponse response = new AuthenticationApi().authorize();
            bearerToken = response.getAccessToken();
            if (DEBUG) {
                System.err.printf("Received Bearer token %s\n", bearerToken);
            }

            // Configure the client library to use the bearer token.
            ApiKeyAuth bearerAuth = (ApiKeyAuth) client.getAuthentication("bearerToken");
            bearerAuth.setApiKey(bearerToken);
            bearerAuth.setApiKeyPrefix("Bearer");
        } catch (ApiException e) {
            System.err.println("Unable to authenticate: " + e.getMessage());
            System.exit(1);
        }

        // Create a RSA key
        SecurityObjectsApi securityObjectsApi = new SecurityObjectsApi();
        SobjectRequest sobjectRequest = new SobjectRequest();
        String newRsaKeyName = UUID.randomUUID().toString();
        sobjectRequest.setName(newRsaKeyName);
        sobjectRequest.setObjType(ObjectType.RSA);
        sobjectRequest.setKeySize(2048);
        System.out.println(String.format("Generating a new RSA key named '%s' ...", newRsaKeyName));
        KeyObject newRsaKeyObject = securityObjectsApi.generateSecurityObject(sobjectRequest);
        String keyId = newRsaKeyObject.getKid();
        System.out.println(String.format("Generated a new RSA key named '%s' with key id: %s", newRsaKeyName, keyId));

        // Get the the key attestation statement of the key just created
        String path = "/crypto/v1/keys/key_attestation"; // API path
        String method = "POST";
        List<Pair> queryParams = new ArrayList<>(); // query parameters
        Object body = String.format("{\"key\":{\"kid\":\"%s\"}}", keyId);
        Map<String, String> headerParams = new HashMap<>(); // header parameters
        Map<String, Object> formParams = new HashMap<>(); // form parameters
        String accept = "application/json";
        String contentType = "application/json";
        String[] authNames = new String[] { "bearerToken" };
        GenericType<KeyAttestationResponse> returnType = new GenericType<KeyAttestationResponse>() {
        };
        System.out.println(String.format("Getting key attestation statement through ..."));
        KeyAttestationResponse keyAttestationResponse = client.invokeAPI(path, method, queryParams, body, headerParams,
                formParams, accept, contentType, authNames, returnType);
        System.out.println("Got key attestation statement");

        // Logout SDKMS ApiClient
        if (bearerToken != null) {
            // It is a good idea to terminate the session when you are done
            // using it. This minimizes the window of time in which an attacker
            // could steal bearer token and use it.
            try {
                new AuthenticationApi().terminate();
            } catch (ApiException e) {
                System.err.println("Error logging out: " + e.getMessage());
            }
            bearerToken = null;
        }

        // Download Fortanix Root CA certificate
        System.out.println("Downloading Fortanix Attestation and Provisioning Root CA certificate form: "
                + Common.FORTANIX_ATTESTATION_AND_PROVISIONING_ROOT_CA_CERT_URL);
        X509Certificate trustedRootCert = Common.getFortanixRootCaCertRemote(
                Common.FORTANIX_ATTESTATION_AND_PROVISIONING_ROOT_CA_CERT_URL);
        System.out.println(String.format("Downloaded Fortanix Attestation and Provisioning Root CA"));

        // Do verification
        Verify.verify(keyAttestationResponse, trustedRootCert, true);
    }

}
