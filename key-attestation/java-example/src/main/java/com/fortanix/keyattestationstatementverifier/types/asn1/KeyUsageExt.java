package com.fortanix.keyattestationstatementverifier.types.asn1;

import java.util.Arrays;
import java.util.EnumSet;

import com.fortanix.keyattestationstatementverifier.KeyAttestationStatementVerifyException;

/**
 * The helper type for checking X509 KeyUsage extension
 */
public class KeyUsageExt {
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

        private KeyUsage(int bitIndex) {
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
    }

    private final EnumSet<KeyUsage> usages = EnumSet.noneOf(KeyUsage.class);

    public KeyUsageExt(boolean[] keyUsageBitArray) {
        if (keyUsageBitArray.length != KeyUsage.values().length) {
            throw new IllegalArgumentException("Invalid length of keyUsageBitArray");
        }

        KeyUsage[] usages = KeyUsage.values();
        for (int i = 0; i < keyUsageBitArray.length; i++) {
            if (keyUsageBitArray[i]) {
                this.usages.add(usages[i]);
            }
        }
    }

    public boolean hasUsage(KeyUsage keyUsage) {
        return usages.contains(keyUsage);
    }

    public boolean hasUsage(KeyUsage[] keyUsageList) {
        return usages.containsAll(Arrays.asList(keyUsageList));
    }

    @Override
    public String toString() {
        return "KeyUsageExt{" + usages + '}';
    }
}
