package com.fortanix.keyattestationstatementverifier.types.asn1;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.Extensions;

import com.fortanix.keyattestationstatementverifier.Common;

/**
 * Java class for representing Fortanix defined ASN1 type:
 * ClusterNodeEnrollmentPolicy
 *
 * <pre>
 *   ClusterNodeEnrollmentPolicy ::= SEQUENCE SIZE (1..MAX) OF NodeEnrollmentPolicyItem
 * </pre>
 */
public class ClusterNodeEnrollmentPolicy extends ASN1Object {
    private NodeEnrollmentPolicyItem[] nodeEnrollmentPolicyItems;

    public NodeEnrollmentPolicyItem[] getNodeEnrollmentPolicyItems() {
        return copy(nodeEnrollmentPolicyItems);
    }

    private static NodeEnrollmentPolicyItem[] copy(NodeEnrollmentPolicyItem[] items) {
        NodeEnrollmentPolicyItem[] result = new NodeEnrollmentPolicyItem[items.length];
        System.arraycopy(items, 0, result, 0, items.length);
        return result;
    }

    public ClusterNodeEnrollmentPolicy(ASN1Sequence seq) {
        this.nodeEnrollmentPolicyItems = new NodeEnrollmentPolicyItem[seq.size()];

        for (int i = 0; i != seq.size(); i++) {
            nodeEnrollmentPolicyItems[i] = NodeEnrollmentPolicyItem.getInstance(seq.getObjectAt(i));
        }
    }

    public ClusterNodeEnrollmentPolicy(NodeEnrollmentPolicyItem item) {
        this.nodeEnrollmentPolicyItems = new NodeEnrollmentPolicyItem[] { item };
    }

    public ClusterNodeEnrollmentPolicy(NodeEnrollmentPolicyItem[] items) {
        this.nodeEnrollmentPolicyItems = copy(items);
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     *
     * <pre>
     * ClusterNodeEnrollmentPolicy ::= SEQUENCE SIZE (1..MAX) OF NodeEnrollmentPolicyItem
     * </pre>
     */
    public ASN1Primitive toASN1Primitive() {
        return new DERSequence(nodeEnrollmentPolicyItems);
    }

    /**
     * Return an ClusterNodeEnrollmentPolicy from the passed in object.
     *
     * @param obj an ClusterNodeEnrollmentPolicy, some form or encoding of one, or
     *            null.
     * @return an ClusterNodeEnrollmentPolicy object, or null if null is passed in.
     */
    public static ClusterNodeEnrollmentPolicy getInstance(
            Object obj) {
        if (obj instanceof ClusterNodeEnrollmentPolicy) {
            return (ClusterNodeEnrollmentPolicy) obj;
        } else if (obj != null) {
            return new ClusterNodeEnrollmentPolicy(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public static ClusterNodeEnrollmentPolicy getInstance(
            ASN1TaggedObject obj,
            boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    /**
     * Retrieve an ClusterNodeEnrollmentPolicy for a passed in Extensions object, if
     * present.
     *
     * @param extensions the extensions object to be examined.
     * @return the ClusterNodeEnrollmentPolicy, null if the extension is not
     *         present.
     */
    public static ClusterNodeEnrollmentPolicy fromExtensions(Extensions extensions) {
        return getInstance(Extensions.getExtensionParsedValue(extensions,
                new ASN1ObjectIdentifier(Common.CLUSTER_NODE_ENROLLMENT_POLICY_OID)));
    }

    public String toString() {
        StringBuffer p = new StringBuffer();
        for (int i = 0; i < nodeEnrollmentPolicyItems.length; i++) {
            if (p.length() != 0) {
                p.append(", ");
            }
            p.append(nodeEnrollmentPolicyItems[i]);
        }

        return "ClusterNodeEnrollmentPolicy: [" + p + "]";
    }
}
