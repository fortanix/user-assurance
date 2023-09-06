package com.fortanix.keyattestationstatementverifier.types.json;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;

public class KeyAttestationResponse {

    /**
     * The DER-encoded certificate chain for the authority issuing the key
     * attestation statement, encoded in Base64 String.
     */
    @JsonProperty("authority_chain")
    private List<String> authorityChain; // Blob as

    /**
     * The key attestation statement.
     */
    @JsonProperty("attestation_statement")
    private KeyAttestationStatement attestationStatement;

    public KeyAttestationResponse() {
    }

    public List<String> getAuthorityChain() {
        return authorityChain;
    }

    public void setAuthorityChain(List<String> authorityChain) {
        this.authorityChain = authorityChain;
    }

    public KeyAttestationResponse(List<String> authorityChain, KeyAttestationStatement attestationStatement) {
        this.authorityChain = authorityChain;
        this.attestationStatement = attestationStatement;
    }

    public KeyAttestationStatement getAttestationStatement() {
        return attestationStatement;
    }

    public void setAttestationStatement(KeyAttestationStatement attestationStatement) {
        this.attestationStatement = attestationStatement;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        KeyAttestationResponse other = (KeyAttestationResponse) obj;
        if (authorityChain == null) {
            if (other.authorityChain != null)
                return false;
        } else if (!authorityChain.equals(other.authorityChain))
            return false;
        if (attestationStatement == null) {
            if (other.attestationStatement != null)
                return false;
        } else if (!attestationStatement.equals(other.attestationStatement))
            return false;
        return true;
    }

    @Override
    public String toString() {
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            return objectMapper.writeValueAsString(this);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
            return super.toString();
        }
    }
}
