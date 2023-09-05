package com.fortanix.keyattestationstatementverifier.types.asn1;

import com.fortanix.keyattestationstatementverifier.KeyAttestationStatementVerifyException;

/**
 * The helper type for checking X509 KeyUsage extension
 */
public enum KeyUsage {
    DIGITAL_SIGNATURE(0),
    NON_REPUDIATION(1),
    KEY_ENCIPHERMENT(2),
    DATA_ENCIPHERMENT(3),
    KEY_AGREEMENT(4),
    KEY_CERT_SIGN(5),
    CRL_SIGN(6),
    ENCIPHER_ONLY(7),
    DECIPHER_ONLY(8);

    final int bitIndex;

    KeyUsage(int bitIndex) {
        this.bitIndex = bitIndex;
    }

    public int getBitIndex() {
        return this.bitIndex;
    }

    @Override
    public String toString() {
        switch (this) {
            case DIGITAL_SIGNATURE:
                return "Digital Signature";
            case NON_REPUDIATION:
                return "Non-Repudiation";
            case KEY_ENCIPHERMENT:
                return "Key Encipherment";
            case DATA_ENCIPHERMENT:
                return "Data Encipherment";
            case KEY_AGREEMENT:
                return "Key Agreement";
            case KEY_CERT_SIGN:
                return "Key Certificate Sign";
            case CRL_SIGN:
                return "CRL Sign";
            case ENCIPHER_ONLY:
                return "Encipher Only";
            case DECIPHER_ONLY:
                return "Decipher Only";
            default:
                throw new IllegalArgumentException();
        }
    }

    public static void checkKeyUsageHelper(String errStrPrefix, boolean[] keyUsage, KeyUsage[] expectedEnabledBits)
            throws KeyAttestationStatementVerifyException {
        if (keyUsage != null && keyUsage.length == 9) {
            for (KeyUsage ku : expectedEnabledBits) {
                if (!keyUsage[ku.bitIndex]) {
                    throw new KeyAttestationStatementVerifyException(
                            errStrPrefix + " keyUsage extension does not contains: " + ku.toString());
                }
            }
        } else {
            throw new KeyAttestationStatementVerifyException(errStrPrefix + " invalid keyUsage extension");
        }
    }
}