package de.flexiprovider.pqc.ecc.mceliece;

import codec.asn1.ASN1Integer;
import codec.asn1.ASN1Null;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1OctetString;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1Type;
import de.flexiprovider.api.keys.PrivateKey;
import de.flexiprovider.common.math.codingtheory.GF2mField;
import de.flexiprovider.common.math.codingtheory.PolynomialGF2mSmallM;
import de.flexiprovider.common.math.linearalgebra.GF2Matrix;
import de.flexiprovider.common.math.linearalgebra.Permutation;
import de.flexiprovider.common.util.ASN1Tools;

/**
 * This class implements a McEliece private key and is usually instantiated by
 * the {@link McElieceKeyPairGenerator} or {@link McElieceKeyFactory}.
 * 
 * @author Elena Klintsevich
 */
public class McEliecePrivateKey extends PrivateKey {

    // the length of the code
    private int n;

    // the dimension of the code, where <tt>k &gt;= n - mt</tt>
    private int k;

    // the underlying finite field
    private GF2mField field;

    // the irreducible Goppa polynomial
    private PolynomialGF2mSmallM goppaPoly;

    // the matrix S^-1
    private GF2Matrix sInv;

    // the permutation P1 used to generate the systematic check matrix
    private Permutation p1;

    // the permutation P2 used to compute the public generator matrix
    private Permutation p2;

    // the canonical check matrix of the code
    private GF2Matrix h;

    // the matrix used to compute square roots in <tt>(GF(2^m))^t</tt>
    private PolynomialGF2mSmallM[] qInv;

    /**
     * Constructor (used by the {@link McElieceKeyPairGenerator}).
     * 
     * @param n
     *                the length of the code
     * @param k
     *                the dimension of the code
     * @param field
     *                the field polynomial defining the finite field
     *                <tt>GF(2<sup>m</sup>)</tt>
     * @param goppaPoly
     *                the irreducible Goppa polynomial
     * @param sInv
     *                the matrix <tt>S<sup>-1</sup></tt>
     * @param p1
     *                the permutation used to generate the systematic check
     *                matrix
     * @param p2
     *                the permutation used to compute the public generator
     *                matrix
     * @param h
     *                the canonical check matrix
     * @param qInv
     *                the matrix used to compute square roots in
     *                <tt>(GF(2<sup>m</sup>))<sup>t</sup></tt>
     */
    protected McEliecePrivateKey(int n, int k, GF2mField field,
	    PolynomialGF2mSmallM goppaPoly, GF2Matrix sInv, Permutation p1,
	    Permutation p2, GF2Matrix h, PolynomialGF2mSmallM[] qInv) {
	this.n = n;
	this.k = k;
	this.field = field;
	this.goppaPoly = goppaPoly;
	this.sInv = sInv;
	this.p1 = p1;
	this.p2 = p2;
	this.h = h;
	this.qInv = qInv;
    }

    /**
     * Constructor (used by the {@link McElieceKeyFactory}).
     * 
     * @param keySpec
     *                a {@link McEliecePrivateKeySpec}
     */
    protected McEliecePrivateKey(McEliecePrivateKeySpec keySpec) {
	this(keySpec.getN(), keySpec.getK(), keySpec.getField(), keySpec
		.getGoppaPoly(), keySpec.getSInv(), keySpec.getP1(), keySpec
		.getP2(), keySpec.getH(), keySpec.getQInv());
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
	return k;
    }

    /**
     * @return the finite field
     */
    protected GF2mField getField() {
	return field;
    }

    /**
     * @return the irreducible Goppa polynomial
     */
    protected PolynomialGF2mSmallM getGoppaPoly() {
	return goppaPoly;
    }

    /**
     * @return the k x k random binary non-singular matrix S
     */
    protected GF2Matrix getSInv() {
	return sInv;
    }

    /**
     * @return the permutation used to generate the systematic check matrix
     */
    protected Permutation getP1() {
	return p1;
    }

    /**
     * @return the permutation used to compute the public generator matrix
     */
    protected Permutation getP2() {
	return p2;
    }

    /**
     * @return the canonical check matrix
     */
    protected GF2Matrix getH() {
	return h;
    }

    /**
     * @return the matrix for computing square roots in <tt>(GF(2^m))^t</tt>
     */
    protected PolynomialGF2mSmallM[] getQInv() {
	return qInv;
    }

    /**
     * @return a human readable form of the key
     */
    public String toString() {
	String result = " length of the code          : " + n + "\n";
	result += " dimension of the code       : " + k + "\n";
	result += " irreducible Goppa polynomial: " + goppaPoly + "\n";
	result += " (k x k)-matrix S^-1         : " + sInv + "\n";
	result += " permutation P1              : " + p1 + "\n";
	result += " permutation P2              : " + p2;
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
	if (!(other instanceof McEliecePrivateKey)) {
	    return false;
	}
	McEliecePrivateKey otherKey = (McEliecePrivateKey) other;

	return (n == otherKey.n) && (k == otherKey.k)
		&& field.equals(otherKey.field)
		&& goppaPoly.equals(otherKey.goppaPoly)
		&& sInv.equals(otherKey.sInv) && p1.equals(otherKey.p1)
		&& p2.equals(otherKey.p2) && h.equals(otherKey.h);
    }

    /**
     * @return the hash code of this key
     */
    public int hashCode() {
	return k + n + field.hashCode() + goppaPoly.hashCode()
		+ sInv.hashCode() + p1.hashCode() + p2.hashCode()
		+ h.hashCode();
    }

    /**
     * @return the OID to encode in the SubjectPublicKeyInfo structure
     */
    protected ASN1ObjectIdentifier getOID() {
	return new ASN1ObjectIdentifier(McElieceKeyFactory.OID);
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
     *   McEliecePrivateKey ::= SEQUENCE {
     *     n          INTEGER                   -- length of the code
     *     k          INTEGER                   -- dimension of the code
     *     fieldPoly  OCTET STRING              -- field polynomial defining GF(2&circ;m)
     *     goppaPoly  OCTET STRING              -- irreducible Goppa polynomial
     *     sInv       OCTET STRING              -- matrix S&circ;-1
     *     p1         OCTET STRING              -- permutation P1
     *     p2         OCTET STRING              -- permutation P2
     *     h          OCTET STRING              -- canonical check matrix
     *     qInv       SEQUENCE OF OCTET STRING  -- matrix used to compute square roots	
     *   }
     * </pre>
     * 
     * @return the key data to encode in the SubjectPublicKeyInfo structure
     */
    protected byte[] getKeyData() {
	ASN1Sequence keyData = new ASN1Sequence();

	// encode <n>
	keyData.add(new ASN1Integer(n));
	// encode <k>
	keyData.add(new ASN1Integer(k));
	// encode <fieldPoly>
	keyData.add(new ASN1OctetString(field.getEncoded()));
	// encode <goppaPoly>
	keyData.add(new ASN1OctetString(goppaPoly.getEncoded()));
	// encode <sInv>
	keyData.add(new ASN1OctetString(sInv.getEncoded()));
	// encode <p1>
	keyData.add(new ASN1OctetString(p1.getEncoded()));
	// encode <p2>
	keyData.add(new ASN1OctetString(p2.getEncoded()));
	// encode <h>
	keyData.add(new ASN1OctetString(h.getEncoded()));
	// encode <qInv>
	ASN1Sequence sqRootSeq = new ASN1Sequence(qInv.length);
	for (int i = 0; i < qInv.length; i++) {
	    sqRootSeq.add(new ASN1OctetString(qInv[i].getEncoded()));
	}
	keyData.add(sqRootSeq);

	return ASN1Tools.derEncode(keyData);
    }

}
