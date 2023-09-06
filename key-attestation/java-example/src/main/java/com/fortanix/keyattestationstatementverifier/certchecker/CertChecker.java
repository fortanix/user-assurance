package com.fortanix.keyattestationstatementverifier.certchecker;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import com.fortanix.keyattestationstatementverifier.Common;
import com.fortanix.keyattestationstatementverifier.KeyAttestationStatementVerifyException;
import com.fortanix.keyattestationstatementverifier.types.asn1.ClusterNodeEnrollmentPolicy;

/**
 * This abstract class represents custom certificate checker
 */
public abstract class CertChecker {
    private static Logger LOGGER = Logger.getLogger(CertChecker.class.getName());

    /**
     * This function should check all details in given certificate `cert`
     *
     * @param cert       Certificate to be checked
     * @param issuerCert Issuer's certificate
     * @throws Exception
     */
    abstract public void check(X509Certificate cert, X509Certificate issuerCert) throws Exception;

    /**
     * Verify the CrlDistPoint extension in given certificate contains expected URL
     *
     * @param errStrPrefix
     * @param cert         Source certificate
     * @param expectedCrl  Expected CRL URL
     * @throws Exception
     */
    protected void verifyDistPoint(String errStrPrefix, X509Certificate cert, String expectedCrl) throws Exception {
        LOGGER.info(String.format("Checking if '%s' certificate's CrlDistPoint contains: %s",
                Common.getCommonName(cert), expectedCrl));
        byte[] crlDistPointExtOctetBytes = cert.getExtensionValue("2.5.29.31");
        if (crlDistPointExtOctetBytes == null) {
            throw new KeyAttestationStatementVerifyException(
                    errStrPrefix
                            + " certificate should contains cRLDistributionPoints extension");
        }
        ASN1OctetString crlDistPointExtOctet = ASN1OctetString.getInstance(crlDistPointExtOctetBytes);
        ASN1InputStream asnInStream = new ASN1InputStream(crlDistPointExtOctet.getOctets());
        CRLDistPoint crlDistPoint = CRLDistPoint.getInstance(asnInStream.readObject());

        DistributionPoint[] distPoints = crlDistPoint.getDistributionPoints();
        if (distPoints.length != 1) {
            throw new KeyAttestationStatementVerifyException(
                    errStrPrefix
                            + " certificate cRLDistributionPoints extension should contains 1 point");
        }
        DistributionPointName actualName = distPoints[0].getDistributionPoint();
        if (actualName.getType() != DistributionPointName.FULL_NAME) {
            throw new KeyAttestationStatementVerifyException(
                    errStrPrefix
                            + " certificate cRLDistributionPoints extension's DistributionPointName should be type of FULL_NAME");
        }
        DistributionPointName expectedName = new DistributionPointName(new GeneralNames(
                new GeneralName(GeneralName.uniformResourceIdentifier, expectedCrl)));
        if (!actualName.equals(expectedName)) {
            throw new KeyAttestationStatementVerifyException(
                    errStrPrefix
                            + " certificate cRLDistributionPoints extension wrong Name");
        }
    }

    /**
     * Check given certificate's SubjectKeyIdentifier extension matches its Public
     * Subject Key info
     *
     * @param cert       Certificate to be checked
     * @param digestAlgo Hash algorithm name used for creating
     *                   SubjectKeyIdentifier
     *
     * @throws Exception
     */
    protected void checkSubjectKeyIdentifier(X509Certificate cert, String digestAlgo)
            throws Exception {
        LOGGER.info(String.format(
                "Checking if '%s' certificate's SubjectKeyIdentifier extension matches its Public Subject Key info",
                Common.getCommonName(cert)));
        byte[] computedSkiVal = getComputedSkiVal(cert, digestAlgo);
        byte[] skiVal = getExtSkiVal(cert);
        // Compare both SKIs
        if (!java.util.Arrays.equals(skiVal, computedSkiVal)) {
            throw new KeyAttestationStatementVerifyException(
                    Common.getCommonName(cert)
                            + " certificate Subject Key Identifier content not match with Subject Public Key");
        }
    }

    /**
     * Get Subject Key Identifier value from certificate extension
     *
     * @param certHolder Source certificate
     * @return Byte array format of Subject Key Identifier value
     * @throws Exception
     */
    protected byte[] getExtSkiVal(X509Certificate cert) throws Exception {
        LOGGER.info(String.format(
                "Getting '%s' certificate's SubjectKeyIdentifier extension",
                Common.getCommonName(cert)));
        X509CertificateHolder certHolder = new JcaX509CertificateHolder(cert);
        SubjectKeyIdentifier ski = SubjectKeyIdentifier.fromExtensions(certHolder.getExtensions());
        if (ski == null) {
            throw new KeyAttestationStatementVerifyException("SubjectKeyIdentifier extension not found");
        }
        return ski.getKeyIdentifier();
    }

    /**
     * Get Authority Key Identifier value from certificate extension
     *
     * @param certHolder Source certificate
     * @return Byte array format of Authority Key Identifier value value
     * @throws Exception Will throw `KeyAttestationStatementVerifyException` if no
     *                   Authority Key Identifier extension found
     */
    protected byte[] getExtAkiVal(X509Certificate cert) throws Exception {
        LOGGER.info(String.format(
                "Getting '%s' certificate's AuthorityKeyIdentifier extension",
                Common.getCommonName(cert)));
        X509CertificateHolder certHolder = new JcaX509CertificateHolder(cert);
        AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.fromExtensions(certHolder.getExtensions());
        if (aki == null) {
            throw new KeyAttestationStatementVerifyException("AuthorityKeyIdentifier extension not found");
        }
        return aki.getKeyIdentifier();
    }

    /**
     * Compute Subject Key Identifier value from certificate's Public Subject Key
     * Info
     *
     * @param cert       Source certificate
     * @param digestAlgo Hash algorithm name used for creating SubjectKeyIdentifier
     * @return
     * @throws Exception
     */
    protected byte[] getComputedSkiVal(X509Certificate cert, String digestAlgo) throws Exception {
        LOGGER.info(String.format(
                "Computing '%s' certificate's Subject Key Identifier value from certificate's Public Subject Key",
                Common.getCommonName(cert)));
        byte[] certPkVal = cert.getPublicKey().getEncoded();
        MessageDigest md = MessageDigest.getInstance(digestAlgo);
        byte[] computedSkiVal = md.digest(certPkVal);
        return computedSkiVal;
    }

    /**
     * Get specific CertificatePolicyInfo from CertificatePolicies extension
     *
     * @param cert             Source certificate
     * @param policyIdentifier Specific OID of CertificatePolicyInfo
     * @return PolicyInformation that matches given OID
     * @throws Exception Will throw `KeyAttestationStatementVerifyException` if no
     *                   specific PolicyInformation found
     */
    protected PolicyInformation getCertificatePolicyInfoByOID(X509Certificate cert,
            ASN1ObjectIdentifier policyIdentifier) throws Exception {
        LOGGER.info(String.format(
                "Getting '%s' certificate's CertificatePolicyInfo with OID: %s from CertificatePolicies extension",
                Common.getCommonName(cert), policyIdentifier.toString()));
        X509CertificateHolder certHolder = new JcaX509CertificateHolder(cert);
        CertificatePolicies certificatePolicies = CertificatePolicies.fromExtensions(certHolder.getExtensions());
        if (certificatePolicies == null) {
            throw new KeyAttestationStatementVerifyException("CertificatePolicies extension not found");
        }
        return certificatePolicies.getPolicyInformation(policyIdentifier);
    }

    /**
     * Check if ExtendedKeyUsage extension contains specific KeyPurposeId
     *
     * @param cert         Source certificate
     * @param keyPurposeId Specific KeyPurposeId, which is type of OID
     * @return If ExtendedKeyUsage has specific KeyPurposeId
     * @throws Exception Will throw `KeyAttestationStatementVerifyException` if no
     *                   ExtendedKeyUsage extension found
     */
    protected boolean checkExtendedKeyUsage(X509Certificate cert, KeyPurposeId keyPurposeId) throws Exception {
        LOGGER.info(String.format(
                "Checking '%s' certificate has extended key usage with OID: %s from ExtendedKeyUsage extension",
                Common.getCommonName(cert), keyPurposeId.toString()));
        X509CertificateHolder certHolder = new JcaX509CertificateHolder(cert);
        ExtendedKeyUsage extendedKeyUsage = ExtendedKeyUsage.fromExtensions(certHolder.getExtensions());
        if (extendedKeyUsage == null) {
            throw new KeyAttestationStatementVerifyException("ExtendedKeyUsage extension not found");
        }
        return extendedKeyUsage.hasKeyPurposeId(keyPurposeId);
    }

    /**
     * Get ClusterNodeEnrollmentPolicy extension
     *
     * @param cert Source certificate
     * @return ClusterNodeEnrollmentPolicy
     * @throws Exception Will throw `KeyAttestationStatementVerifyException` if no
     *                   ClusterNodeEnrollmentPolicy extension found
     */
    protected ClusterNodeEnrollmentPolicy getClusterNodeEnrollmentPolicy(X509Certificate cert) throws Exception {
        LOGGER.info(String.format(
                "Getting '%s' certificate's ClusterNodeEnrollmentPolicy extension (OID: %s)",
                Common.getCommonName(cert), Common.CLUSTER_NODE_ENROLLMENT_POLICY_OID));
        X509CertificateHolder certHolder = new JcaX509CertificateHolder(cert);
        ClusterNodeEnrollmentPolicy clusterNodeEnrollmentPolicy = ClusterNodeEnrollmentPolicy
                .fromExtensions(certHolder.getExtensions());
        if (clusterNodeEnrollmentPolicy == null) {
            throw new KeyAttestationStatementVerifyException("ClusterNodeEnrollmentPolicy extension not found");
        }
        return clusterNodeEnrollmentPolicy;
    }
}
