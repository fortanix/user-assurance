package com.fortanix.keyattestationstatementverifier.types.json;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class KeyAttestationStatement {

    /**
     * The format of the `statement` field.
     */
    @JsonProperty("format")
    private KeyAttestationStatementFormat format;

    /**
     * The key attestation statement formatted according to `format`, encoded in
     * Base64 String.
     */
    @JsonProperty("statement")
    private String statement; // Blob as

    public KeyAttestationStatement() {
    }

    public KeyAttestationStatement(KeyAttestationStatementFormat format, String statement) {
        this.format = format;
        this.statement = statement;
    }

    public KeyAttestationStatementFormat getFormat() {
        return format;
    }

    public void setFormat(KeyAttestationStatementFormat format) {
        this.format = format;
    }

    public String getStatement() {
        return statement;
    }

    public void setStatement(String statement) {
        this.statement = statement;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        KeyAttestationStatement other = (KeyAttestationStatement) obj;
        if (format != other.format)
            return false;
        if (statement == null) {
            if (other.statement != null)
                return false;
        } else if (!statement.equals(other.statement))
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
