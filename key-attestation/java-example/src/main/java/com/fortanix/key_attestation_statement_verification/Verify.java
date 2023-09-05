package com.fortanix.key_attestation_statement_verification;

import java.io.FileReader;
import java.io.Reader;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;

import com.fortanix.key_attestation_statement_verification.certchecker.CertChecker;
import com.fortanix.key_attestation_statement_verification.certchecker.DsmKeyAttestationAuthorityCertChecker;
import com.fortanix.key_attestation_statement_verification.certchecker.FortanixRootCertChecker;
import com.fortanix.key_attestation_statement_verification.certchecker.KeyAttestationCaCertChecker;
import com.fortanix.key_attestation_statement_verification.certchecker.KeyAttestationStatementCertChecker;

public final class Verify {
    private static final Logger LOGGER = Logger.getLogger(Verify.class.getName());

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Verify given `attestationStatement`, `authorityChain` by using `trustRootCa`
     *
     * @param authorityChain       Certificate chain of all certificates expect
     *                             `Fortanix Key Attestation Statement` certificate
     * @param attestationStatement `Fortanix Key Attestation Statement` certificate
     * @param trustRootCa          Trusted root CA, you need to get the certificate
     *                             from Fortanix PKI website
     * @param verifyCrl            If check the CRL, need network access
     * @throws Exception
     */
    public static void verify(List<X509Certificate> authorityChain, X509Certificate attestationStatement,
            X509Certificate trustRootCa, boolean verifyCrl) throws Exception {
        checkAuthorityChainLength(authorityChain);

        LOGGER.info("Checking if root certificate in `authorityChain` matches given trusted root certificate");
        check_root_cert_match(authorityChain.get(authorityChain.size() - 1), trustRootCa);
        // verify each signature on authority certificate chain is correctly signed by
        // it's parent
        try {
            verify_cert_chain_signature(authorityChain, trustRootCa, verifyCrl);
            System.out.println("The signature in 'Fortanix DSM Key Attestation' certificate is valid.");
        } catch (Exception e) {
            throw new KeyAttestationStatementVerifyException(
                    "The signature in 'Fortanix DSM Key Attestation' certificate is valid, " + e.toString());
        }
        LOGGER.info(String.format("Checking if '%s' certificate is correctly signed by '%s' certificate",
                Common.DSM_CLUSTER_KEY_ATTESTATION_AUTHORITY_CN, Common.KEY_ATTESTATION_STATEMENT_CN));
        // because 'Fortanix DSM SaaS Key Attestation Authority' is not a CA
        // certificate, so we need to manually check 'Fortanix DSM Key Attestation' is
        // correctly singed by 'Fortanix DSM SaaS Key Attestation Authority' certificate
        verify_cert_signature(attestationStatement, authorityChain.get(0));

        CertChecker statementChecker = new KeyAttestationStatementCertChecker();
        CertChecker authorityChecker = new DsmKeyAttestationAuthorityCertChecker();
        CertChecker caChecker = new KeyAttestationCaCertChecker();
        CertChecker rooCertChecker = new FortanixRootCertChecker();
        statementChecker.check(attestationStatement, authorityChain.get(0));
        // 1st certificate in the chain should be 'Fortanix DSM SaaS Key Attestation
        // Authority' certificate
        authorityChecker.check(authorityChain.get(0), authorityChain.get(1));
        // 2nd certificate in the chain should be 'Fortanix Key Attestation CA'
        // certificate
        caChecker.check(authorityChain.get(1), authorityChain.get(2));
        // 3rd certificate in the chain should be 'Fortanix Attestation and Provisioning
        // Root CA' certificate
        rooCertChecker.check(authorityChain.get(2), authorityChain.get(2));
    }

    /**
     * Verify the signature in given certificate chain from leaf node to trusted CA
     * certificate
     *
     * @param chain    Certificate chain to verify
     * @param trust_ca The trusted CA certificate
     * @throws Exception
     */
    public static void verify_cert_chain_signature(List<X509Certificate> chain, X509Certificate trust_ca,
            boolean verifyCrl)
            throws Exception {
        LOGGER.info("Checking if root certificate in `authorityChain` matches given trusted root certificate");
        if (chain.isEmpty()) {
            throw new KeyAttestationStatementVerifyException("Empty certificate chain");
        }
        // Create CertPath
        CertificateFactory factory = CertificateFactory.getInstance("X.509", "BC");
        CertPath certPath = factory.generateCertPath(chain);

        // Set up TrustAnchor using the last certificate as the root certificate
        TrustAnchor trustAnchor = new TrustAnchor(trust_ca, null);
        Set<TrustAnchor> trustAnchors = Collections.singleton(trustAnchor);

        // Set up PKIXParameters
        PKIXParameters params = new PKIXParameters(trustAnchors);
        params.setRevocationEnabled(verifyCrl);

        // Validate CertPath
        CertPathValidator validator = CertPathValidator.getInstance("PKIX", "BC");
        try {
            validator.validate(certPath, params);
        } catch (CertPathValidatorException e) {
            // Handle validation exception
            throw new KeyAttestationStatementVerifyException("Certificate chain validation failed" + e.toString());
        }
    }

    /**
     * Helper function to check if given trusted Root CA certificate matches the
     * final parent CA certificate in the `authorityChain`
     *
     * @param root_cert The final parent CA certificate in the `authorityChain`
     * @param trust_ca  Trusted Root CA certificate
     * @throws Exception
     */
    public static void check_root_cert_match(X509Certificate root_cert, X509Certificate trust_ca) throws Exception {
        if (!root_cert.equals(trust_ca)) {
            LOGGER.warning("Actual root cert:\n" + root_cert.toString());
            LOGGER.warning("Expected root cert:\n" + trust_ca.toString());
            throw new KeyAttestationStatementVerifyException(
                    "Root CA certificate in chain does not match trust ca certificate");
        }
    }

    /**
     * Helper function to read a certificate chain from the path to a PEM formatted
     * file
     *
     * @param pemFilePath The path to a PEM formatted file
     * @return A list of X509Certificate
     * @throws Exception
     */
    public static List<X509Certificate> readPemCertsFromPath(String pemFilePath) throws Exception {
        LOGGER.info(String.format("Reading PEM certificates from %s ...", pemFilePath));
        Reader reader = new FileReader(pemFilePath);
        return readPemCertsFromReader(reader);
    }

    /**
     * Helper function to read a certificate chain from a Reader
     *
     * @param reader java Reader of the data of certificate chain
     * @return A list of X509Certificate
     * @throws Exception
     */
    public static List<X509Certificate> readPemCertsFromReader(Reader reader) throws Exception {
        LOGGER.info(String.format("Reading PEM certificates from %s ...", reader.toString()));
        List<X509CertificateHolder> certChain = new ArrayList<>();
        try (PEMParser pemParser = new PEMParser(reader)) {
            Object object = pemParser.readObject();
            while (object != null) {
                if (object instanceof X509CertificateHolder) {
                    X509CertificateHolder cert = (X509CertificateHolder) object;
                    if (!certChain.add(cert)) {
                        throw new KeyAttestationStatementVerifyException("Failed to add new Certificate");
                    }
                } else {
                    throw new KeyAttestationStatementVerifyException(
                            "Found a non Certificate PEM object: " + object.toString());
                }
                object = pemParser.readObject();
            }
            pemParser.close();
        }
        if (certChain.isEmpty()) {
            throw new KeyAttestationStatementVerifyException("No valid Certificate in given file");
        }
        return convertX509CertificateHolders(certChain);
    }

    /**
     * Helper function to convert a List of
     * org.bouncycastle.cert.X509CertificateHolder to a List of
     * java.security.cert.X509Certificate
     *
     * @param cert_chain List of certificate to be converted
     * @return A List of java.security.cert.X509Certificate
     * @throws Exception
     */
    public static List<X509Certificate> convertX509CertificateHolders(List<X509CertificateHolder> cert_chain)
            throws Exception {
        LOGGER.info("Converting List<X509CertificateHolder> to List<X509Certificate> ...");
        // Convert X509CertificateHolder to Certificate for CertPath
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME);
        List<X509Certificate> chain = new ArrayList<>();
        for (X509CertificateHolder holder : cert_chain) {
            X509Certificate cert = converter.getCertificate(holder);
            LOGGER.fine("Converted cert:\n" + cert.toString());
            chain.add(cert);
        }
        return chain;
    }

    /**
     * Helper function to check the length of authority certificate chain.
     *
     * @param authorityCertChain Certificate chain to be checked
     * @throws KeyAttestationStatementVerifyException
     */
    private static void checkAuthorityChainLength(List<X509Certificate> authorityCertChain)
            throws KeyAttestationStatementVerifyException {
        int authorityCertChainSize = authorityCertChain.size();
        LOGGER.info(String.format("Checking authorityCertChain size: %d == %d ?", authorityCertChainSize,
                Common.VALID_AUTHORITY_CERT_CHAIN_NUM));
        if (authorityCertChainSize != Common.VALID_AUTHORITY_CERT_CHAIN_NUM) {
            throw new KeyAttestationStatementVerifyException(
                    String.format(
                            "A valid authority certificates chain should contain %d certificate",
                            Common.DSM_CLUSTER_KEY_ATTESTATION_AUTHORITY_CN));
        }
    }

    /**
     * Helper function to check if given child certificate is correctly signed by
     * it's issuer
     *
     * @param child  Certificate to be validated
     * @param parent The certificate of issuer
     * @throws Exception
     */
    public static void verify_cert_signature(X509Certificate child, X509Certificate parent)
            throws Exception {
        PublicKey parentPublicKey = parent.getPublicKey();
        child.verify(parentPublicKey);
    }
}
