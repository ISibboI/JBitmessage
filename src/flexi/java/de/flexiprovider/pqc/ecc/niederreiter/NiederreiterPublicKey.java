package de.flexiprovider.pqc.ecc.niederreiter;

import codec.asn1.ASN1Integer;
import codec.asn1.ASN1Null;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1OctetString;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1Type;
import de.flexiprovider.api.keys.PublicKey;
import de.flexiprovider.common.math.linearalgebra.GF2Matrix;
import de.flexiprovider.common.util.ASN1Tools;

/**
 * This class implements a Niederreiter public key and is usually instantiated
 * by the {@link NiederreiterKeyPairGenerator}.
 * 
 * @author Elena Klintsevich
 * @see NiederreiterKeyPairGenerator
 * @see NiederreiterPublicKey
 */
public class NiederreiterPublicKey extends PublicKey {

    /**
     * the length of the code
     */
    private int n;

    /**
     * the error correction capability of the code
     */
    private int t;

    /**
     * the check matrix
     */
    private GF2Matrix h;

    /**
     * Constructor, used by {@link NiederreiterKeyPairGenerator}.
     * 
     * @param n
     *                length of the code
     * @param t
     *                error correction capability of the code
     * @param h
     *                check matrix
     */
    protected NiederreiterPublicKey(int n, int t, GF2Matrix h) {
	this.n = n;
	this.t = t;
	this.h = h;
    }

    /**
     * Constructor, used by {@link NiederreiterKeyFactory}.
     * 
     * @param keySpec
     *                a {@link NiederreiterPublicKeySpec}
     */
    protected NiederreiterPublicKey(NiederreiterPublicKeySpec keySpec) {
	this(keySpec.getN(), keySpec.getT(), keySpec.getH());

    }

    /**
     * Return the name of the algorithm.
     * 
     * @return "Niederreiter"
     */
    public String getAlgorithm() {
	return "Niederreiter";
    }

    /**
     * @return the length of the code
     */
    public int getN() {
	return n;
    }

    /**
     * @return the error correction capability of the code
     */
    public int getT() {
	return t;
    }

    /**
     * @return the dimension of the code
     */
    public int getK() {
	return h.getNumRows();
    }

    /**
     * @return the check matrix
     */
    public GF2Matrix getH() {
	return h;
    }

    /**
     * @return a human readable form of the key.
     */
    public String toString() {
	String result = "length of the code: " + n + "\n";
	result += "error correction capability: " + t + "\n";
	result += "check matrix: " + h;
	return result;
    }

    /**
     * Compare this key with another object.
     * 
     * @param other
     *                the other object
     * @return the result of the comparison
     */
    public boolean equals(Object other) {
	if (other == null || !(other instanceof NiederreiterPublicKey)) {
	    return false;
	}
	NiederreiterPublicKey otherKey = (NiederreiterPublicKey) other;

	return (t == otherKey.t) && (n == otherKey.n) && h.equals(otherKey.h);
    }

    /**
     * @return the hash code of this key
     */
    public int hashCode() {
	return n + t + h.hashCode();
    }

    /**
     * @return the OID to encode in the SubjectPublicKeyInfo structure
     */
    protected ASN1ObjectIdentifier getOID() {
	return new ASN1ObjectIdentifier(NiederreiterKeyFactory.OID);
    }

    /**
     * @return the algorithm parameters to encode in the SubjectPublicKeyInfo
     *         structure
     */
    protected ASN1Type getAlgParams() {
	return new ASN1Null();
    }

    /**
     * Return the key data to encode in the SubjectPublicKeyInfo structure.
     * <p>
     * The ASN.1 definition of the key structure is
     * 
     * <pre>
     * NiederreiterPublicKey ::= SEQUENCE {
     *   n   INTEGER       -- the length of the code
     *   t   INTEGER       -- the error correcting capability
     *   h   OCTET STRING  -- the encoded check matrix
     * }
     * </pre>
     * 
     * @return the keyData to encode in the SubjectPublicKeyInfo structure
     */
    protected byte[] getKeyData() {
	ASN1Sequence keyData = new ASN1Sequence();

	// encode <n>
	keyData.add(new ASN1Integer(n));

	// encode <t>
	keyData.add(new ASN1Integer(t));

	// encode <matrixH>
	keyData.add(new ASN1OctetString(h.getEncoded()));

	return ASN1Tools.derEncode(keyData);
    }

}
