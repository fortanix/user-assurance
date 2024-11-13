# Java example code for how to verify Fortanix DSM Key Attestation Statement

This is a example java of how to verify **Fortanix DSM Key Attestation Statement** properly.

## Building

`mvn -B package`

## Testing

- Run offline tests:
    - `mvn test`
- Run online tests:
    - `mvn test -Dtest=VerifyTestLive`
- Because the certificates stored in repo are already expired, to test the successful code path with [`faketime`](https://manpages.ubuntu.com/manpages/trusty/man1/faketime.1.html):
    - `./run_faketime_tests.sh`

## Explanation

The test code under [VerifyTest.java](src/test/java/com/fortanix/keyattestationstatementverifier/VerifyTest.java)
shows how to properly verify the  **Fortanix DSM Key Attestation Statement** certificate offline:

- `verifyStatementFromJsonWithoutCrlCheck`: Verify given `KeyAttestationResponse` in a JSON file, assuming the last certificate in authority chain is correct ROOT certificate and skipping CRL checks.

The test code under [VerifyTestLive.java](src/test/java/com/fortanix/keyattestationstatementverifier/VerifyTest.java)
shows how to properly verify the  **Fortanix DSM Key Attestation Statement** certificate online:

- `verifyStatementFullCheckOnlineAMER`: Use https://amer.smartkey.io to create a RSA key and get attestation statement of it.Then it verifies the statement with root CA downloaded from https://pki.fortanix.com/Fortanix_Attestation_and_Provisioning_Root_CA.crt.