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
 * This class implements a McEliece CCA2 private key and is usually instantiated
 * by the {@link McElieceCCA2KeyPairGenerator} or {@link McElieceCCA2KeyFactory}.
 * 
 * @see McElieceCCA2KeyPairGenerator
 * @author Elena Klintsevich
 * @author Martin Döring
 */
public class McElieceCCA2PrivateKey extends PrivateKey {

    // the length of the code
    private int n;

    // the dimension of the code, k>=n-mt
    private int k;

    // the finte field GF(2^m)
    private GF2mField field;

    // the irreducible Goppa polynomial
    private PolynomialGF2mSmallM goppaPoly;

    // the permutation
    private Permutation p;

    // the canonical check matrix
    private GF2Matrix h;

    // the matrix used to compute square roots in (GF(2^m))^t
    private PolynomialGF2mSmallM[] qInv;

    /**
     * Constructor (used by the {@link McElieceCCA2KeyPairGenerator}).
     * 
     * @param n
     *                the length of the code
     * @param k
     *                the dimension of the code
     * @param field
     *                the field polynomial
     * @param gp
     *                the irreducible Goppa polynomial
     * @param p
     *                the permutation
     * @param h
     *                the canonical check matrix
     * @param qInv
     *                the matrix used to compute square roots in
     *                <tt>(GF(2^m))^t</tt>
     */
    protected McElieceCCA2PrivateKey(int n, int k, GF2mField field,
	    PolynomialGF2mSmallM gp, Permutation p, GF2Matrix h,
	    PolynomialGF2mSmallM[] qInv) {
	this.n = n;
	this.k = k;
	this.field = field;
	this.goppaPoly = gp;
	this.p = p;
	this.h = h;
	this.qInv = qInv;
    }

    /**
     * Constructor (used by the {@link McElieceCCA2KeyFactory}).
     * 
     * @param keySpec
     *                a {@link McElieceCCA2PrivateKeySpec}
     */
    protected McElieceCCA2PrivateKey(McElieceCCA2PrivateKeySpec keySpec) {
	this(keySpec.getN(), keySpec.getK(), keySpec.getField(), keySpec
		.getGoppaPoly(), keySpec.getP(), keySpec.getH(), keySpec
		.getQInv());
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
     * @return the degree of the Goppa polynomial (error correcting capability)
     */
    protected int getT() {
	return goppaPoly.getDegree();
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
     * @return the permutation vector
     */
    protected Permutation getP() {
	return p;
    }

    /**
     * @return the canonical check matrix
     */
    protected GF2Matrix getH() {
	return h;
    }

    /**
     * @return the matrix used to compute square roots in <tt>(GF(2^m))^t</tt>
     */
    protected PolynomialGF2mSmallM[] getQInv() {
	return qInv;
    }

    /**
     * @return a human readable form of the key
     */
    public String toString() {
	String result = "";
	result += " extension degree of the field      : " + n + "\n";
	result += " dimension of the code              : " + k + "\n";
	result += " irreducible Goppa polynomial       : " + goppaPoly + "\n";
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
	if (other == null || !(other instanceof McElieceCCA2PrivateKey)) {
	    return false;
	}

	McElieceCCA2PrivateKey otherKey = (McElieceCCA2PrivateKey) other;

	return (n == otherKey.n) && (k == otherKey.k)
		&& field.equals(otherKey.field)
		&& goppaPoly.equals(otherKey.goppaPoly) && p.equals(otherKey.p)
		&& h.equals(otherKey.h);
    }

    /**
     * @return the hash code of this key
     */
    public int hashCode() {
	return k + n + field.hashCode() + goppaPoly.hashCode() + p.hashCode()
		+ h.hashCode();
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
     *   McEliecePrivateKey ::= SEQUENCE {
     *     m             INTEGER                  -- extension degree of the field
     *     k             INTEGER                  -- dimension of the code
     *     field         OCTET STRING             -- field polynomial
     *     goppaPoly     OCTET STRING             -- irreducible Goppa polynomial
     *     p             OCTET STRING             -- permutation vector
     *     matrixH       OCTET STRING             -- canonical check matrix
     *     sqRootMatrix  SEQUENCE OF OCTET STRING -- square root matrix	
     *   }
     * </pre>
     * 
     * @return the keyData to encode in the SubjectPublicKeyInfo structure
     */
    protected byte[] getKeyData() {
	ASN1Sequence keyData = new ASN1Sequence();

	// encode <n>
	keyData.add(new ASN1Integer(n));
	// encode <k>
	keyData.add(new ASN1Integer(k));
	// encode <field>
	keyData.add(new ASN1OctetString(field.getEncoded()));
	// encode <gp>
	keyData.add(new ASN1OctetString(goppaPoly.getEncoded()));
	// encode <p>
	keyData.add(new ASN1OctetString(p.getEncoded()));
	// encode <h>
	keyData.add(new ASN1OctetString(h.getEncoded()));
	// encode <q>
	ASN1Sequence qSeq = new ASN1Sequence(qInv.length);
	for (int i = 0; i < qInv.length; i++) {
	    qSeq.add(new ASN1OctetString(qInv[i].getEncoded()));
	}
	keyData.add(qSeq);

	return ASN1Tools.derEncode(keyData);
    }

}
