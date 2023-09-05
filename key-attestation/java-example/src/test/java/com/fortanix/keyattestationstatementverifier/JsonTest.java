package com.fortanix.keyattestationstatementverifier;

import org.junit.Test;

import com.fortanix.keyattestationstatementverifier.types.json.KeyAttestationResponse;
import com.fortanix.keyattestationstatementverifier.types.json.KeyAttestationStatement;
import com.fortanix.keyattestationstatementverifier.types.json.KeyAttestationStatementFormat;
import com.fasterxml.jackson.databind.ObjectMapper;

import static org.junit.Assert.*;

import java.util.Arrays;
import java.util.List;

public class JsonTest {
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    public void testKeyAttestationResponseJsonEncodingDecoding() throws Exception {
        // Create sample data
        List<String> authorityChain = Arrays.asList("certChain1", "certChain2");
        String statementString = "statement1";
        KeyAttestationStatement keyAttestationStatement = new KeyAttestationStatement(
                KeyAttestationStatementFormat.X509_CERTIFICATE, statementString);

        // Encode to JSON
        KeyAttestationResponse response = new KeyAttestationResponse(authorityChain, keyAttestationStatement);
        String jsonString = objectMapper.writeValueAsString(response);

        // Expected JSON
        String expectedJson = "{\"authority_chain\":[\"certChain1\",\"certChain2\"],\"attestation_statement\":{\"format\":\"x509_certificate\",\"statement\":\"statement1\"}}";

        // Assert that the encoded JSON string matches the expected JSON
        assertEquals(expectedJson, jsonString);

        // Decode from JSON
        KeyAttestationResponse decodedResponse = objectMapper.readValue(jsonString, KeyAttestationResponse.class);

        // Assert that the original and decoded objects are equal
        assertEquals(response.getAuthorityChain(), decodedResponse.getAuthorityChain());
        assertEquals(response.getAttestationStatement(), decodedResponse.getAttestationStatement());
    }
}
