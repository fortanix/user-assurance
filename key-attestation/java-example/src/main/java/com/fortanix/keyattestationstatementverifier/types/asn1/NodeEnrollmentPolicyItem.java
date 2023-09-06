package com.fortanix.keyattestationstatementverifier.types.asn1;

import org.bouncycastle.asn1.*;

/**
 * Java class for representing Fortanix defined ASN1 type:
 * NodeEnrollmentPolicyItem
 *
 * <pre>
 *   NodeEnrollmentPolicyItem ::= SEQUENCE {
 *   policyItem OBJECT IDENTIFIER,
 *   qualifiers ANY DEFINED BY policyItem OPTIONAL }
 * </pre>
 */
public class NodeEnrollmentPolicyItem extends ASN1Object {
    private ASN1ObjectIdentifier policyItem;
    private ASN1Encodable qualifiers;

    private NodeEnrollmentPolicyItem(ASN1Sequence seq) {
        if (seq.size() < 1 || seq.size() > 2) {
            throw new IllegalArgumentException("Bad sequence size: "
                    + seq.size());
        }

        policyItem = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));

        if (seq.size() > 1) {
            qualifiers = seq.getObjectAt(1);
        }
    }

    public NodeEnrollmentPolicyItem(ASN1ObjectIdentifier policyItem) {
        this.policyItem = policyItem;
    }

    public NodeEnrollmentPolicyItem(ASN1ObjectIdentifier policyItem, ASN1Encodable qualifiers) {
        this.policyItem = policyItem;
        this.qualifiers = qualifiers;
    }

    public static NodeEnrollmentPolicyItem getInstance(Object obj) {
        if (obj == null || obj instanceof NodeEnrollmentPolicyItem) {
            return (NodeEnrollmentPolicyItem) obj;
        }

        return new NodeEnrollmentPolicyItem(ASN1Sequence.getInstance(obj));
    }

    public ASN1ObjectIdentifier getPolicyItem() {
        return policyItem;
    }

    public ASN1Encodable getQualifiers() {
        return qualifiers;
    }

    /*
     * <pre>
     * NodeEnrollmentPolicyItem ::= SEQUENCE {
     * policyItem OBJECT IDENTIFIER,
     * qualifiers ANY DEFINED BY policyItem OPTIONAL }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vec = new ASN1EncodableVector(2);
        vec.add(policyItem);
        if (qualifiers != null) {
            vec.add(qualifiers);
        }
        return new DERSequence(vec);
    }

    public String toString() {
        StringBuffer sb = new StringBuffer();

        sb.append("NodeEnrollmentPolicyItem: ");
        sb.append(policyItem);

        if (qualifiers != null) {
            sb.append(qualifiers);
        }

        return sb.toString();
    }
}
