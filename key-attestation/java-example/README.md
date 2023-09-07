# Java example code for how to verify Fortanix DSM Key Attestation Statement

This is a example java of how to verify **Fortanix DSM Key Attestation Statement** properly.

## Building

`mvn compile`

## Testing

`mvn test`

## Explanation

The test code under [VerifyTest.java](src/test/java/com/fortanix/keyattestationstatementverifier/VerifyTest.java)
shows how to properly verify the  **Fortanix DSM Key Attestation Statement** certificate:

Online check
- `verifyStatementFullCheck`: Verify given `KeyAttestationResponse` in a JSON file, the `Fortanix Attestation and Provisioning Root CA` is downloaded from https://pki.fortanix.com in runtime. **Note**: This test is turned off since CRL and PKI server is not ready when this example code is created and certificates for testing are signed by fake CA.

Offline check
- `verifyStatementFromJsonWithoutCrlCheck`: Verify given `KeyAttestationResponse` in a JSON file, assuming the last certificate in authority chain is correct ROOT certificate and skipping CRL checks.
