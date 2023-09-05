package com.fortanix.keyattestationstatementverifier.certchecker;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import com.fortanix.keyattestationstatementverifier.Common;
import com.fortanix.keyattestationstatementverifier.KeyAttestationStatementVerifyException;
import com.fortanix.keyattestationstatementverifier.types.asn1.ClusterNodeEnrollmentPolicy;
import com.fortanix.keyattestationstatementverifier.types.asn1.KeyUsage;
import com.fortanix.keyattestationstatementverifier.types.asn1.NodeEnrollmentPolicyItem;

public class DsmKeyAttestationAuthorityCertChecker extends CertChecker {
    private static final Logger LOGGER = Logger.getLogger(DsmKeyAttestationAuthorityCertChecker.class.getName());
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
        X500Name authorityCertSubject = certHolder.getSubject();
        if (!Common.checkNameMatch(authorityCertSubject, Common.DSM_CLUSTER_KEY_ATTESTATION_AUTHORITY_NAME)) {
            throw new KeyAttestationStatementVerifyException(
                    Common.DSM_CLUSTER_KEY_ATTESTATION_AUTHORITY_CN + " certificate subject is invalid:\n"
                            + authorityCertSubject.toString());
        }
        // check issuer
        X500Name authorityCertIssuer = certHolder.getIssuer();
        if (!Common.checkNameMatch(authorityCertIssuer, Common.FORTANIX_KEY_ATTESTATION_CA_NAME)) {
            throw new KeyAttestationStatementVerifyException(
                    Common.DSM_CLUSTER_KEY_ATTESTATION_AUTHORITY_CN + " certificate issuer is invalid:\n"
                            + authorityCertIssuer.toString() + "\n!=\n"
                            + Common.FORTANIX_KEY_ATTESTATION_CA_NAME.toString());
        }
    }

    private void check_public_key(X509Certificate cert) throws Exception {
        PublicKey authorityPk = cert.getPublicKey();
        if (authorityPk instanceof RSAPublicKey) {
            RSAPublicKey authorityRsaPk = (RSAPublicKey) authorityPk;
            assert (authorityRsaPk.getModulus().bitLength() >= 3072);
        } else {
            throw new KeyAttestationStatementVerifyException(
                    Common.DSM_CLUSTER_KEY_ATTESTATION_AUTHORITY_CN + " certificate invalid public key type");
        }

    }

    private void check_extensions(X509Certificate cert, X509Certificate issuerCert) throws Exception {
        // check extension: Key Usage
        LOGGER.info(String.format(
                "Checking '%s' certificate's KeyUsages extension", certCN));
        KeyUsage[] authorityCertExpectedKeyUsage = { KeyUsage.DIGITAL_SIGNATURE };
        KeyUsage.checkKeyUsageHelper(Common.DSM_CLUSTER_KEY_ATTESTATION_AUTHORITY_CN, cert.getKeyUsage(),
                authorityCertExpectedKeyUsage);
        // check extension: Basic Constraints
        LOGGER.info(String.format(
                "Checking '%s' certificate's BasicConstraints extension", certCN));
        int pathLenConstraint = cert.getBasicConstraints();
        if (pathLenConstraint != -1) {
            throw new KeyAttestationStatementVerifyException(
                    Common.DSM_CLUSTER_KEY_ATTESTATION_AUTHORITY_CN
                            + " certificate has invalid BasicConstraints extension, it should not be a CA");

        }
        // check extension: CRL Distribution Points
        verifyDistPoint(Common.DSM_CLUSTER_KEY_ATTESTATION_AUTHORITY_CN, cert,
                Common.FORTANIX_KEY_ATTESTATION_CA_CRL_URL);
        // check extension: Subject Key Identifier
        checkSubjectKeyIdentifier(cert, "SHA-1");
        // check extension: Authority Key Identifier
        if (!Arrays.equals(getExtAkiVal(cert), getExtSkiVal(issuerCert))) {
            throw new KeyAttestationStatementVerifyException(
                    Common.DSM_CLUSTER_KEY_ATTESTATION_AUTHORITY_CN
                            + " certificate Authority Key Identifier extension has wrong value");
        }
        // check extension: Certificate Policies
        if (getCertificatePolicyInfoByOID(cert,
                new ASN1ObjectIdentifier(Common.FORTANIX_KEY_ATTESTATION_CERTIFICATE_POLICY_OID)) == null) {
            throw new KeyAttestationStatementVerifyException(String.format(
                    "%s certificate Extended Key Usage extension should contain: Fortanix Key Attestation Certificate Policy (%s)",
                    Common.DSM_CLUSTER_KEY_ATTESTATION_AUTHORITY_CN,
                    Common.FORTANIX_KEY_ATTESTATION_CERTIFICATE_POLICY_OID));
        }
        // check extension: Extended Key Usage
        if (!checkExtendedKeyUsage(cert,
                KeyPurposeId.getInstance(new ASN1ObjectIdentifier(Common.ID_KP_FORTANIX_KEY_ATTESTATION)))) {
            throw new KeyAttestationStatementVerifyException(String.format(
                    "%s certificate Extended Key Usage extension should contain KeyPurposeId: id-kp-fortanix-key-attestation (%s)",
                    Common.DSM_CLUSTER_KEY_ATTESTATION_AUTHORITY_CN, Common.ID_KP_FORTANIX_KEY_ATTESTATION));
        }
        // check extension: Cluster node enrollment policy
        ClusterNodeEnrollmentPolicy clusterNodeEnrollmentPolicy = getClusterNodeEnrollmentPolicy(cert);
        NodeEnrollmentPolicyItem[] nodeEnrollmentPolicyItem = clusterNodeEnrollmentPolicy
                .getNodeEnrollmentPolicyItems();
        if (nodeEnrollmentPolicyItem.length < 2) {
            throw new KeyAttestationStatementVerifyException(Common.DSM_CLUSTER_KEY_ATTESTATION_AUTHORITY_CN
                    + " certificate 'Cluster node enrollment policy' extension should at least contain 2 policy items, but get: "
                    + nodeEnrollmentPolicyItem.length);
        }
        ASN1ObjectIdentifier policyItem1 = nodeEnrollmentPolicyItem[0].getPolicyItem();
        if (!policyItem1.getId().equals(Common.NODE_ENROLLMENT_POLICY_ITEM_MINIMUM_PROTECTION_PROFILE_OID)) {
            throw new KeyAttestationStatementVerifyException(String.format(
                    "%s certificate 'Cluster node enrollment policy' extension should contain policy item 'Node enrollment policy item: Minimum protection profile' (%s), but get: %s",
                    Common.DSM_CLUSTER_KEY_ATTESTATION_AUTHORITY_CN,
                    Common.NODE_ENROLLMENT_POLICY_ITEM_MINIMUM_PROTECTION_PROFILE_OID,
                    policyItem1.getId()));
        }

        ASN1ObjectIdentifier policyItem1Qualifier = ASN1ObjectIdentifier
                .getInstance(nodeEnrollmentPolicyItem[0].getQualifiers());
        if (!policyItem1Qualifier.getId()
                .equals(Common.NODE_ENROLLMENT_POLICY_ITEM_WELL_KNOWN_PROTECTION_PROFILE_FORTANIX_FX2200_OID)) {
            throw new KeyAttestationStatementVerifyException(String.format(
                    "%s certificate 'Cluster node enrollment policy' extension policy item 'Node enrollment policy item: Minimum protection profile' should contain qualifier: 'Well-known protection profile: Fortanix FX2200' (%s), but get: %s",
                    Common.DSM_CLUSTER_KEY_ATTESTATION_AUTHORITY_CN,
                    Common.NODE_ENROLLMENT_POLICY_ITEM_WELL_KNOWN_PROTECTION_PROFILE_FORTANIX_FX2200_OID,
                    policyItem1.getId()));
        }
        ASN1ObjectIdentifier policyItem2 = nodeEnrollmentPolicyItem[1].getPolicyItem();
        if (!policyItem2.getId().equals(Common.NODE_ENROLLMENT_POLICY_ITEM_SITE_OPERATOR_APPROVAL_REQUIRED_OID)) {
            throw new KeyAttestationStatementVerifyException(String.format(
                    "%s certificate 'Cluster node enrollment policy' extension should contain policy item 'Node enrollment policy item: Site operator approval required' (%s), but get: %s",
                    Common.DSM_CLUSTER_KEY_ATTESTATION_AUTHORITY_CN,
                    Common.NODE_ENROLLMENT_POLICY_ITEM_SITE_OPERATOR_APPROVAL_REQUIRED_OID,
                    policyItem1.getId()));
        }
    }

}
