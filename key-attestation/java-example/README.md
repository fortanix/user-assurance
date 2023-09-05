# Java example code for how to verify Fortanix DSM Key Attestation Statement

This is a example java of how to verify **Fortanix DSM Key Attestation Statement** properly.

## Building

`mvn compile`

## Testing

`mvn test`

## Explanation

The test code under [VerifyTest.java](src/test/java/com/fortanix/keyattestationstatementverifier/VerifyTest.java)
shows how to properly verify the  **Fortanix DSM Key Attestation Statement** certificate:
- `verifyStatementWithoutCrlCheck` for offline verification
- `verifyStatementFullCheck` for online verification

# License

This project is primarily distributed under the terms of the Apache License
version 2.0 and the GNU General Public License version 2, see
[LICENSE-APACHE](./LICENSE-APACHE) and [LICENSE-GPL](./LICENSE-GPL) for
details.