package de.flexiprovider.pqc.ecc.mceliece;

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
 * This class implements a McEliece CCA2 public key and is usually instantiated
 * by the {@link McElieceCCA2KeyPairGenerator} or {@link McElieceCCA2KeyFactory}.
 * 
 * @author Elena Klintsevich
 * @author Martin Döring
 */
public class McElieceCCA2PublicKey extends PublicKey {

    // the length of the code
    private int n;

    // the error correction capability of the code
    private int t;

    // the generator matrix
    private GF2Matrix g;

    /**
     * Constructor (used by the {@link McElieceCCA2KeyPairGenerator}).
     * 
     * @param n
     *                the length of the code
     * @param t
     *                the error correction capability of the code
     * @param g
     *                the generator matrix
     */
    protected McElieceCCA2PublicKey(int n, int t, GF2Matrix g) {
	this.n = n;
	this.t = t;
	this.g = g;
    }

    /**
     * Constructor (used by the {@link McElieceCCA2KeyFactory}).
     * 
     * @param keySpec
     *                a {@link McElieceCCA2PublicKeySpec}
     */
    protected McElieceCCA2PublicKey(McElieceCCA2PublicKeySpec keySpec) {
	this(keySpec.getN(), keySpec.getT(), keySpec.getMatrixG());
    }

    /**
     * Return the name of the algorithm.
     * 
     * @return "McEliece"
     */
    public String getAlgorithm() {
	return "McEliece";
    }

    /**
     * @return the length of the code
     */
    protected int getN() {
	return n;
    }

    /**
     * @return the dimension of the code
     */
    protected int getK() {
	return g.getNumRows();
    }

    /**
     * @return the error correction capability of the code
     */
    protected int getT() {
	return t;
    }

    /**
     * @return the generator matrix
     */
    protected GF2Matrix getG() {
	return g;
    }

    /**
     * @return a human readable form of the key
     */
    public String toString() {
	String result = "McEliecePublicKey:\n";
	result += " length of the code         : " + n + "\n";
	result += " error correction capability: " + t + "\n";
	result += " generator matrix           : " + g.toString();
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
	if (other == null || !(other instanceof McElieceCCA2PublicKey)) {
	    return false;
	}

	McElieceCCA2PublicKey otherKey = (McElieceCCA2PublicKey) other;

	return (n == otherKey.n) && (t == otherKey.t) && (g.equals(otherKey.g));
    }

    /**
     * @return the hash code of this key
     */
    public int hashCode() {
	return n + t + g.hashCode();
    }

    /**
     * @return the OID to encode in the SubjectPublicKeyInfo structure
     */
    protected ASN1ObjectIdentifier getOID() {
	return new ASN1ObjectIdentifier(McElieceCCA2KeyFactory.OID);
    }

    /**
     * @return the algorithm parameters to encode in the SubjectPublicKeyInfo
     *         structure
     */
    protected ASN1Type getAlgParams() {
	return new ASN1Null();
    }

    /**
     * Return the keyData to encode in the SubjectPublicKeyInfo structure.
     * <p>
     * The ASN.1 definition of the key structure is
     * 
     * <pre>
     *       McEliecePublicKey ::= SEQUENCE {
     *         n           Integer      -- length of the code
     *         t           Integer      -- error correcting capability
     *         matrixG     OctetString  -- generator matrix as octet string
     *       }
     * </pre>
     * 
     * @return the keyData to encode in the SubjectPublicKeyInfo structure
     */
    protected byte[] getKeyData() {
	ASN1Sequence keyData = new ASN1Sequence();
	keyData.add(new ASN1Integer(n));
	keyData.add(new ASN1Integer(t));
	keyData.add(new ASN1OctetString(g.getEncoded()));
	return ASN1Tools.derEncode(keyData);
    }

}
