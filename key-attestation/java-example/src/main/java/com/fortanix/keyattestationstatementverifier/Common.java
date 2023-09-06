package com.fortanix.keyattestationstatementverifier;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

public class Common {
    public static final String FORTANIX_PKI_DOMAIN = "pki.fortanix.com";
    public static final String FORTANIX_ATTESTATION_AND_PROVISIONING_ROOT_CA_CERT_URL = String
            .format("https://%s/Fortanix_Attestation_and_Provisioning_Root_CA.crt", FORTANIX_PKI_DOMAIN);
    public static final String FORTANIX_KEY_ATTESTATION_CA_CRL_URL = String
            .format("https://%s/Fortanix_Key_Attestation_CA.crl", FORTANIX_PKI_DOMAIN);
    public static final String FORTANIX_ATTESTATION_AND_PROVISIONING_ROOT_CA_CRL_URL = String
            .format("https://%s/Fortanix_Attestation_and_Provisioning_Root_CA.crl", FORTANIX_PKI_DOMAIN);

    public static final String ID_KP_FORTANIX_KEY_ATTESTATION = "1.3.6.1.4.1.49690.8.1";
    public static final String CLUSTER_NODE_ENROLLMENT_POLICY_OID = "1.3.6.1.4.1.49690.2.5";
    /**
     * Node enrollment policy item: Minimum protection profile
     */
    public static final String NODE_ENROLLMENT_POLICY_ITEM_MINIMUM_PROTECTION_PROFILE_OID = "1.3.6.1.4.1.49690.2.5.1";
    /**
     * One of qualifiers of 'Node enrollment policy item: Minimum protection
     * profile': Well-known protection profile: Fortanix FX2200
     */
    public static final String NODE_ENROLLMENT_POLICY_ITEM_WELL_KNOWN_PROTECTION_PROFILE_FORTANIX_FX2200_OID = "1.3.6.1.4.1.49690.2.5.1.1";
    /**
     * Node enrollment policy item: Site operator approval required
     */
    public static final String NODE_ENROLLMENT_POLICY_ITEM_SITE_OPERATOR_APPROVAL_REQUIRED_OID = "1.3.6.1.4.1.49690.2.5.2";
    public static final String FORTANIX_KEY_ATTESTATION_CERTIFICATE_POLICY_OID = "1.3.6.1.4.1.49690.6.1.2";

    public static final int VALID_AUTHORITY_CERT_CHAIN_NUM = 3;
    public static final String FORTANIX_ATTESTATION_AND_PROVISIONING_ROOT_CA_CN = "Fortanix Attestation and Provisioning Root CA";
    public static final String FORTANIX_KEY_ATTESTATION_CA_CN = "Fortanix Key Attestation CA";
    public static final String DSM_CLUSTER_KEY_ATTESTATION_AUTHORITY_CN = "Fortanix DSM SaaS Key Attestation Authority";
    public static final String KEY_ATTESTATION_STATEMENT_CN = "Fortanix DSM Key Attestation";
    public static final String FORTANIX_SUBJECT_C = "US";
    public static final String FORTANIX_SUBJECT_ST = "California";
    public static final String FORTANIX_SUBJECT_L = "Santa Clara";
    public static final String FORTANIX_SUBJECT_O = "Fortanix, Inc.";
    public static X500Name FORTANIX_ATTESTATION_AND_PROVISIONING_ROOT_CA_NAME;
    public static X500Name FORTANIX_KEY_ATTESTATION_CA_NAME;
    public static X500Name DSM_CLUSTER_KEY_ATTESTATION_AUTHORITY_NAME;
    public static X500Name KEY_ATTESTATION_STATEMENT_NAME;

    static {
        Common.FORTANIX_ATTESTATION_AND_PROVISIONING_ROOT_CA_NAME = buildX500Name(
                Common.FORTANIX_SUBJECT_C,
                Common.FORTANIX_SUBJECT_ST,
                Common.FORTANIX_SUBJECT_L,
                Common.FORTANIX_SUBJECT_O,
                Common.FORTANIX_ATTESTATION_AND_PROVISIONING_ROOT_CA_CN);
        Common.FORTANIX_KEY_ATTESTATION_CA_NAME = buildX500Name(
                Common.FORTANIX_SUBJECT_C,
                Common.FORTANIX_SUBJECT_ST,
                Common.FORTANIX_SUBJECT_L,
                Common.FORTANIX_SUBJECT_O,
                Common.FORTANIX_KEY_ATTESTATION_CA_CN);
        Common.DSM_CLUSTER_KEY_ATTESTATION_AUTHORITY_NAME = buildX500Name(
                "", "", "", "",
                Common.DSM_CLUSTER_KEY_ATTESTATION_AUTHORITY_CN);
        Common.KEY_ATTESTATION_STATEMENT_NAME = buildX500Name(
                "", "", "", "",
                Common.KEY_ATTESTATION_STATEMENT_CN);

    }

    /**
     * Helper function to build expected Name
     *
     * @param c  Country
     * @param st State or province
     * @param l  Locality
     * @param o  Organization name
     * @param cn Common name
     * @return
     */
    private static X500Name buildX500Name(String c, String st, String l, String o, String cn) {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        // Set the values for county, stateOrProvince, locality, organization and
        // commonName
        if (!c.isEmpty()) {
            builder.addRDN(BCStyle.C, c);
        }
        if (!st.isEmpty()) {
            builder.addRDN(BCStyle.ST, st);
        }
        if (!l.isEmpty()) {
            builder.addRDN(BCStyle.L, l);
        }
        if (!o.isEmpty()) {
            builder.addRDN(BCStyle.O, o);
        }
        builder.addRDN(BCStyle.CN, cn);

        return builder.build();
    }

    /**
     * Check if given Name contains all expected Name
     *
     * @param actual   Actual Name
     * @param expected Expected Name
     * @return
     * @throws Exception
     */
    public static boolean checkNameMatch(X500Name actual, X500Name expected) throws Exception {
        ASN1ObjectIdentifier[] styles = { BCStyle.C, BCStyle.ST, BCStyle.L, BCStyle.O, BCStyle.CN };

        for (ASN1ObjectIdentifier style : styles) {
            if (!checkRDNsMatch(actual, expected, style)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Helper function to check if specific Subject Name is matched. This is needed
     * for get rid of difference between UTF8String and PrintableString
     *
     * @param actual   Actual Name
     * @param expected Expected Name
     * @param style    Specific RDN type
     * @return
     * @throws Exception
     */
    private static boolean checkRDNsMatch(X500Name actual, X500Name expected, ASN1ObjectIdentifier style)
            throws Exception {
        RDN[] actualRDNs = actual.getRDNs(style);
        RDN[] expectedRDNs = expected.getRDNs(style);

        if (expectedRDNs.length != 0) {
            if (actualRDNs.length != 0) {
                String actualValue = actualRDNs[0].getFirst().getValue().toString();
                String expectedValue = expectedRDNs[0].getFirst().getValue().toString();

                if (!actualValue.equals(expectedValue)) {
                    return false;
                }
            } else {
                return false;
            }
        }

        return true;
    }

    /**
     * Helper function to check if given URL is a valid URL to Fortanix PKI
     *
     * @param urlString URL to be checked
     * @throws Exception Will throw KeyAttestationStatementVerifyException if URL is
     *                   invalid
     */
    public static void isValidCrlUrl(String urlString) throws Exception {
        URL url = new URL(urlString);
        if (!url.getProtocol().equals("https")) {
            throw new KeyAttestationStatementVerifyException("invalid CRL URL: should be https");
        }
        if (!url.getHost().equalsIgnoreCase(FORTANIX_PKI_DOMAIN)) {
            throw new KeyAttestationStatementVerifyException("invalid CRL URL: invalid domain");
        }
        if (!url.getPath().endsWith(".crl")) {
            throw new KeyAttestationStatementVerifyException("invalid CRL URL: should be end with '.crl'");
        }
    }

    /**
     * Helper function to retrieve remote content from URL into a String
     *
     * @param url URL to get content from
     * @return Data in type of sting
     * @throws Exception
     */
    public static String getUrlContentsInString(URL url) throws Exception {
        // create a URLConnection object
        URLConnection urlConnection = url.openConnection();

        // wrap the URLConnection in a BufferedReader
        BufferedReader bufferedReader = new BufferedReader(
                new InputStreamReader(urlConnection.getInputStream(), StandardCharsets.UTF_8));

        StringBuilder content = new StringBuilder();
        String line;
        // read from the URLConnection via the BufferedReader
        while ((line = bufferedReader.readLine()) != null) {
            content.append(line + "\n");
        }
        bufferedReader.close();

        return content.toString();
    }

    /**
     * Get FortanixRootCaCert from given remote URL
     *
     * @param rootCertUrlStr Given remote URL to FortanixRootCaCert
     * @return Decoded Certificate from remote
     * @throws Exception
     */
    public static X509Certificate getFortanixRootCaCertRemote(String rootCertUrlStr) throws Exception {
        URL url = new URL(rootCertUrlStr);
        if (!url.getProtocol().equals("https")) {
            throw new KeyAttestationStatementVerifyException("Fortanix Root CA certificate URL must use HTTPS");
        }
        String pem = getUrlContentsInString(url);
        List<X509Certificate> certs = Verify.readPemCertsFromReader(new StringReader(pem));
        if (certs.size() != 1) {
            throw new KeyAttestationStatementVerifyException(
                    "Fortanix Root CA certificate pem data should only contains one certificate");
        }
        return certs.get(0);
    }

    /**
     * Helper function to get CN string from a certificate
     * @param cert Source certificate
     * @return Common Name (CN) of the given certificate
     * @throws Exception
     */
    public static String getCommonName(X509Certificate cert) throws Exception {
        X500Name x500name = new JcaX509CertificateHolder(cert).getSubject();
        return x500name.getRDNs(BCStyle.CN)[0].getFirst().getValue().toString();
    }
}
