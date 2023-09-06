package com.fortanix.keyattestationstatementverifier.certchecker;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.logging.Logger;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import com.fortanix.keyattestationstatementverifier.Common;
import com.fortanix.keyattestationstatementverifier.KeyAttestationStatementVerifyException;
import com.fortanix.keyattestationstatementverifier.types.asn1.KeyUsage;

public class FortanixRootCertChecker extends CertChecker {
    private static final Logger LOGGER = Logger.getLogger(FortanixRootCertChecker.class.getName());
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
        check_extensions(cert);
    }

    private void check_subject_and_issuer(X509Certificate cert) throws Exception {
        X509CertificateHolder certHolder = new JcaX509CertificateHolder(cert);

        // check subject
        X500Name rootCertSubject = certHolder.getSubject();
        if (!Common.checkNameMatch(rootCertSubject, Common.FORTANIX_ATTESTATION_AND_PROVISIONING_ROOT_CA_NAME)) {
            throw new KeyAttestationStatementVerifyException(
                    Common.FORTANIX_ATTESTATION_AND_PROVISIONING_ROOT_CA_CN + " certificate subject is invalid "
                            + rootCertSubject.toString());
        }

        // check issuer
        X500Name rootCertIssuer = certHolder.getIssuer();
        if (!Common.checkNameMatch(rootCertIssuer, Common.FORTANIX_ATTESTATION_AND_PROVISIONING_ROOT_CA_NAME)) {
            throw new KeyAttestationStatementVerifyException(
                    Common.FORTANIX_ATTESTATION_AND_PROVISIONING_ROOT_CA_CN + " certificate issuer is invalid "
                            + rootCertIssuer.toString());
        }
    }

    private void check_public_key(X509Certificate cert) throws Exception {
        PublicKey rootPk = cert.getPublicKey();
        if (rootPk instanceof RSAPublicKey) {
            RSAPublicKey rootRsaPk = (RSAPublicKey) rootPk;
            assert (rootRsaPk.getModulus().bitLength() >= 4096);
        } else {
            throw new KeyAttestationStatementVerifyException(
                    Common.FORTANIX_ATTESTATION_AND_PROVISIONING_ROOT_CA_CN
                            + " certificate invalid public key type");
        }
    }

    private void check_extensions(X509Certificate cert) throws Exception {
        // check extension: Key Usage
        LOGGER.info(String.format(
                "Checking '%s' certificate's KeyUsages extension", certCN));
        KeyUsage[] rootCertExpectedKeyUsage = { KeyUsage.DIGITAL_SIGNATURE, KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN };
        KeyUsage.checkKeyUsageHelper(Common.FORTANIX_ATTESTATION_AND_PROVISIONING_ROOT_CA_CN, cert.getKeyUsage(),
                rootCertExpectedKeyUsage);
        int pathLenConstraint = cert.getBasicConstraints();
        // check extension: Basic Constraints
        LOGGER.info(String.format(
                "Checking '%s' certificate's BasicConstraints extension", certCN));
        if (pathLenConstraint < 0) {
            throw new KeyAttestationStatementVerifyException(
                    Common.FORTANIX_ATTESTATION_AND_PROVISIONING_ROOT_CA_CN
                            + " certificate has invalid BasicConstraints extension, it should be a CA");

        }
        if (pathLenConstraint != Integer.MAX_VALUE) {
            throw new KeyAttestationStatementVerifyException(
                    Common.FORTANIX_ATTESTATION_AND_PROVISIONING_ROOT_CA_CN
                            + " certificate has invalid BasicConstraints extension, it'a CA but pathLenConstraint should be absent");
        }
        checkSubjectKeyIdentifier(cert, "SHA-1");
    }

}
