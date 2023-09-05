package com.fortanix.keyattestationstatementverifier.certchecker;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import com.fortanix.keyattestationstatementverifier.Common;
import com.fortanix.keyattestationstatementverifier.KeyAttestationStatementVerifyException;
import com.fortanix.keyattestationstatementverifier.types.asn1.KeyUsage;

public class KeyAttestationCaCertChecker extends CertChecker {
    private static final Logger LOGGER = Logger.getLogger(KeyAttestationCaCertChecker.class.getName());
    private String certCN;

    @Override
    public void check(X509Certificate cert, X509Certificate issuerCert) throws Exception {
        LOGGER.info("Checking certificate content:\n" + cert.toString());
        certCN = Common.getCommonName(cert);
        LOGGER.info(String.format(
                "Checking '%s' certificate's Validity", certCN));
        cert.checkValidity();
        LOGGER.info(String.format(
                "Checking '%s' certificate's Subject & Issuer", certCN));
        check_subject_and_issuer(cert);
        LOGGER.info(String.format(
                "Checking '%s' certificate's Public key length & type", certCN));
        check_public_key(cert);
        LOGGER.info(String.format(
                "Checking '%s' certificate's extensions", certCN));
        check_extensions(cert, issuerCert);
    }

    private void check_subject_and_issuer(X509Certificate cert) throws Exception {
        X509CertificateHolder certHolder = new JcaX509CertificateHolder(cert);
        // check subject
        X500Name caCertSubject = certHolder.getSubject();

        if (!Common.checkNameMatch(caCertSubject, Common.FORTANIX_KEY_ATTESTATION_CA_NAME)) {
            throw new KeyAttestationStatementVerifyException(
                    Common.FORTANIX_KEY_ATTESTATION_CA_CN + " certificate subject is invalid "
                            + caCertSubject.toString());
        }

        // check issuer
        X500Name caCertIssuer = certHolder.getIssuer();
        if (!Common.checkNameMatch(caCertIssuer, Common.FORTANIX_ATTESTATION_AND_PROVISIONING_ROOT_CA_NAME)) {
            throw new KeyAttestationStatementVerifyException(
                    Common.FORTANIX_KEY_ATTESTATION_CA_CN + " certificate issuer is invalid "
                            + caCertIssuer.toString());
        }

    }

    private void check_public_key(X509Certificate cert) throws Exception {
        PublicKey caPk = cert.getPublicKey();
        if (caPk instanceof RSAPublicKey) {
            RSAPublicKey caRsaPk = (RSAPublicKey) caPk;
            assert (caRsaPk.getModulus().bitLength() >= 3072);
        } else {
            throw new KeyAttestationStatementVerifyException(
                    Common.FORTANIX_KEY_ATTESTATION_CA_CN + " certificate invalid public key type");
        }

    }

    private void check_extensions(X509Certificate cert, X509Certificate issuerCert) throws Exception {
        // check extension: Key Usage
        LOGGER.info(String.format(
                "Checking '%s' certificate's KeyUsages extension", certCN));
        KeyUsage[] caCertExpectedKeyUsage = { KeyUsage.DIGITAL_SIGNATURE, KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN };
        KeyUsage.checkKeyUsageHelper(Common.FORTANIX_KEY_ATTESTATION_CA_CN, cert.getKeyUsage(),
                caCertExpectedKeyUsage);
        // check extension: Basic Constraints
        LOGGER.info(String.format(
                "Checking '%s' certificate's BasicConstraints extension", certCN));
        int pathLenConstraint = cert.getBasicConstraints();
        if (pathLenConstraint < 0) {
            throw new KeyAttestationStatementVerifyException(
                    Common.FORTANIX_KEY_ATTESTATION_CA_CN
                            + " certificate has invalid BasicConstraints extension, it should be a CA");

        }
        if (pathLenConstraint != Integer.MAX_VALUE) {
            throw new KeyAttestationStatementVerifyException(
                    Common.FORTANIX_KEY_ATTESTATION_CA_CN
                            + " certificate has invalid BasicConstraints extension, it'a CA but pathLenConstraint should be absent");
        }
        // check extension: CRL Distribution Points
        verifyDistPoint(Common.FORTANIX_KEY_ATTESTATION_CA_CN, cert,
                Common.FORTANIX_ATTESTATION_AND_PROVISIONING_ROOT_CA_CRL_URL);

        // check extension: Subject Key Identifier
        checkSubjectKeyIdentifier(cert, "SHA-1");
        // check extension: Authority Key Identifier
        if (!Arrays.equals(getExtAkiVal(cert), getExtSkiVal(issuerCert))) {
            throw new KeyAttestationStatementVerifyException(
                    Common.FORTANIX_KEY_ATTESTATION_CA_CN
                            + " certificate Authority Key Identifier extension has wrong value");
        }

        // check extension: Certificate Policies
        if (getCertificatePolicyInfoByOID(cert,
                new ASN1ObjectIdentifier(Common.FORTANIX_KEY_ATTESTATION_CERTIFICATE_POLICY_OID)) == null) {
            throw new KeyAttestationStatementVerifyException(String.format(
                    "%s certificate Extended Key Usage extension should contain: Fortanix Key Attestation Certificate Policy (%s)",
                    Common.FORTANIX_KEY_ATTESTATION_CA_CN,
                    Common.FORTANIX_KEY_ATTESTATION_CERTIFICATE_POLICY_OID));
        }
    }

}
