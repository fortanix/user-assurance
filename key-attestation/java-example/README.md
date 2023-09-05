# Java example code for how to verify Fortanix DSM Key Attestation Statement

This is a example java of how to verify **Fortanix DSM Key Attestation Statement** properly.

## Building

`mvn compile`

## Testing

`mvn test`

## Explanation

The test code under [VerifyTest.java](src/test/java/com/fortanix/keyattestationstatementverifier/VerifyTest.java)
shows how to properly verify the  **Fortanix DSM Key Attestation Statement** certificate:

- `verifyStatementFromJsonWithoutCrlCheck`: Verify given `KeyAttestationResponse` in a JSON file, assuming the last certificate in authority chain is correct ROOT certificate and skipping CRL checks.
- `verifyStatementFullCheck`: Verify given `KeyAttestationResponse` in a JSON file, the `Fortanix Attestation and Provisioning Root CA` is downloaded from https://pki.fortanix.com in runtime.
- `verifyStatementFromPemWithoutCrlCheck`: Verify given statement and authority chain in a PEM file, the `Fortanix Attestation and Provisioning Root CA` is downloaded from https://pki.fortanix.com in runtime.

# License

This project is primarily distributed under the terms of the Apache License
version 2.0 and the GNU General Public License version 2, see
[LICENSE-APACHE](./LICENSE-APACHE) and [LICENSE-GPL](./LICENSE-GPL) for
details.