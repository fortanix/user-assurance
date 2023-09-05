package com.fortanix.key_attestation_statement_verification.certchecker;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import com.fortanix.key_attestation_statement_verification.Common;
import com.fortanix.key_attestation_statement_verification.KeyAttestationStatementVerifyException;
import com.fortanix.key_attestation_statement_verification.types.KeyUsage;

public class KeyAttestationStatementCertChecker extends CertChecker {
    @Override
    public void check(X509Certificate cert, X509Certificate issuerCert) throws Exception {
        cert.checkValidity();
        check_subject_and_issuer(cert);
        check_public_key(cert);
        check_extensions(cert, issuerCert);
    }

    private void check_subject_and_issuer(X509Certificate cert) throws Exception {
        X509CertificateHolder statementCert = new JcaX509CertificateHolder(cert);
        // check subject
        X500Name statementCertSubject = statementCert.getSubject();
        if (!Common.checkNameMatch(statementCertSubject, Common.KEY_ATTESTATION_STATEMENT_NAME)) {
            throw new KeyAttestationStatementVerifyException(
                    Common.KEY_ATTESTATION_STATEMENT_CN + " certificate subject is invalid " +
                            statementCertSubject.toString());
        }
        // check issuer

        X500Name statementCertIssuer = statementCert.getIssuer();
        if (!Common.checkNameMatch(statementCertIssuer, Common.DSM_CLUSTER_KEY_ATTESTATION_AUTHORITY_NAME)) {
            throw new KeyAttestationStatementVerifyException(
                    Common.KEY_ATTESTATION_STATEMENT_CN + " certificate issuer is invalid "
                            + statementCertIssuer.toString());
        }
    }

    private void check_public_key(X509Certificate cert) throws Exception {
        PublicKey statementPk = cert.getPublicKey();
        if (statementPk instanceof RSAPublicKey) {
            RSAPublicKey statementRsaPk = (RSAPublicKey) statementPk;
            assert (statementRsaPk.getModulus().bitLength() >= 2048);
        } else {
            throw new KeyAttestationStatementVerifyException(
                    Common.KEY_ATTESTATION_STATEMENT_CN + " certificate invalid public key type");
        }

    }

    private void check_extensions(X509Certificate cert, X509Certificate issuerCert) throws Exception {
        checkCertKeyUsages(cert);
        // check extension: Authority Key Identifier
        if (!Arrays.equals(getExtAkiVal(cert), getExtSkiVal(issuerCert))) {
            throw new KeyAttestationStatementVerifyException(
                    Common.KEY_ATTESTATION_STATEMENT_CN
                            + " certificate Authority Key Identifier extension has wrong value");
        }
    }

    private void checkCertKeyUsages(X509Certificate cert) throws KeyAttestationStatementVerifyException {
        boolean[] certKeyUsagesBooleans = cert.getKeyUsage();
        if (certKeyUsagesBooleans != null && certKeyUsagesBooleans.length == 9) {
            KeyUsage[] allowedKeyUsages = {
                    KeyUsage.DIGITAL_SIGNATURE,
                    KeyUsage.KEY_ENCIPHERMENT,
                    KeyUsage.DATA_ENCIPHERMENT,
                    KeyUsage.KEY_AGREEMENT,
            };
            Set<KeyUsage> allowedKeyUsagesSet = Arrays.stream(allowedKeyUsages).collect(Collectors.toSet());

            KeyUsage[] disallowedKeyUsages = Arrays.stream(KeyUsage.values())
                    .filter(keyUsage -> !allowedKeyUsagesSet.contains(keyUsage))
                    .toArray(KeyUsage[]::new);
            for (KeyUsage ku : disallowedKeyUsages) {
                if (certKeyUsagesBooleans[ku.getBitIndex()]) {
                    throw new KeyAttestationStatementVerifyException(
                            Common.KEY_ATTESTATION_STATEMENT_CN + " keyUsage extension should not contain: "
                                    + ku.toString());
                }
            }
        } else {
            throw new KeyAttestationStatementVerifyException(
                    Common.KEY_ATTESTATION_STATEMENT_CN + " invalid keyUsage extension");
        }
    }

}