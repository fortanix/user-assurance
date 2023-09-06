package com.fortanix.keyattestationstatementverifier.types.json;

import com.fasterxml.jackson.annotation.JsonProperty;

public enum KeyAttestationStatementFormat {

    /**
     * The attestation statement is formatted as a DER-encoded X.509 certificate.
     */
    @JsonProperty("x509_certificate")
    X509_CERTIFICATE
}
