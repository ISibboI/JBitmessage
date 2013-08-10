package de.flexiprovider.pqc.ecc.niederreiter;

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
 * This class implements a Niederreiter private key and is usually instantiated
 * from the {@link NiederreiterKeyPairGenerator}.
 * 
 * @author Elena Klintsevich
 * @see NiederreiterKeyPairGenerator
 * @see NiederreiterPrivateKey
 */
public class NiederreiterPrivateKey extends PrivateKey {

    /**
     * the extension degree of the field
     */
    private int m;

    /**
     * the dimension of the code, where <tt>k &gt;= n - mt</tt>
     */
    private int k;

    /**
     * the underlying finite field
     */
    private GF2mField field;

    /**
     * an irreducible Goppa polynomial
     */
    private PolynomialGF2mSmallM gp;

    /**
     * the matrix used to compute square roots in <tt>(GF(2^m))^t</tt>
     */
    private PolynomialGF2mSmallM[] qInv;

    /**
     * a k x k random binary non-singular matrix
     */
    private GF2Matrix s;

    /**
     * a permutation vector
     */
    private Permutation p;

    /**
     * Constructor, used by {@link NiederreiterKeyPairGenerator}.
     * 
     * @param m
     *                extension degree of the field
     * @param k
     *                dimension of the code
     * @param field
     *                finite field
     * @param gp
     *                irreducible Goppa polynomial
     * @param qInv
     *                matrix used to compute square roots in
     *                <tt>(GF(2<sup>m</sup>))<sup>t</sup></tt>
     * @param sInv
     *                random non-singular matrix S<sup>-1</sup>
     * @param p
     *                permutation P
     */
    protected NiederreiterPrivateKey(int m, int k, GF2mField field,
	    PolynomialGF2mSmallM gp, PolynomialGF2mSmallM[] qInv,
	    GF2Matrix sInv, Permutation p) {
	this.k = k;
	this.m = m;
	this.field = field;
	this.gp = gp;
	this.qInv = qInv;
	this.s = sInv;
	this.p = p;
    }

    /**
     * Constructor, used by {@link NiederreiterKeyFactory}.
     * 
     * @param keySpec
     *                a {@link NiederreiterPrivateKeySpec}
     */
    protected NiederreiterPrivateKey(NiederreiterPrivateKeySpec keySpec) {
	this(keySpec.getM(), keySpec.getK(), keySpec.getField(), keySpec
		.getGoppaPoly(), keySpec.getQInv(), keySpec.getSInv(), keySpec
		.getP());
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
     * @return the extension degree of the field
     */
    public int getM() {
	return m;
    }

    /**
     * @return the dimension of the code
     */
    public int getK() {
	return k;
    }

    /**
     * @return the error correction capability of the code
     */
    public int getT() {
	return gp.getDegree();
    }

    /**
     * @return the length of the code
     */
    public int getN() {
	return 1 << m;
    }

    /**
     * @return the underlying field
     */
    public GF2mField getField() {
	return field;
    }

    /**
     * @return the irreducible Goppa polynomial
     */
    public PolynomialGF2mSmallM getGoppaPoly() {
	return gp;
    }

    /**
     * @return the random non-singular matrix S<sup>-1</sup>
     */
    public GF2Matrix getSInv() {
	return s;
    }

    /**
     * @return the permutation P
     */
    public Permutation getP() {
	return p;
    }

    /**
     * @return the matrix used to compute square roots in
     *         <tt>(GF(2<sup>m</sup>))<sup>t</sup></tt>
     */
    public PolynomialGF2mSmallM[] getQInv() {
	return qInv;
    }

    /**
     * @return a human readable form of the key.
     */
    public String toString() {
	String result = "";
	result += " extension degree of the field      : " + m + "\n";
	result += " dimension of the code              : " + k + "\n";
	result += " irreducible Goppa polynomial       : " + gp + "\n";
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
	if (other == null || !(other instanceof NiederreiterPrivateKey)) {
	    return false;
	}

	NiederreiterPrivateKey otherKey = (NiederreiterPrivateKey) other;

	return (k == otherKey.k) && (m == otherKey.m)
		&& (field.equals(otherKey.field)) && (gp.equals(otherKey.gp))
		&& (s.equals(otherKey.s)) && (p.equals(otherKey.p));
    }

    /**
     * @return the hash code of this key
     */
    public int hashCode() {
	return k + m + field.hashCode() + gp.hashCode() + s.hashCode()
		+ p.hashCode();
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
     *       NiederreiterPrivateKey ::= SEQUENCE {
     *         m             Integer       -- extension degree of the field
     *         k             Integer       -- dimension of the code
     *         field         OCTET STRING  -- encoded field polynomial
     *         irrGoppaPoly  OCTET STRING  -- encoded Goppa polynomial
     *         sInv          OCTET STRING  -- encoded random non-singular matrix
     *         p             OCTET STRING  -- encoded permutation
     *         qInv          OCTET STRING  -- encoded matrix used to compute square roots  
     *       }
     * </pre>
     * 
     * @return the keyData to encode in the SubjectPublicKeyInfo structure
     */
    protected byte[] getKeyData() {
	ASN1Sequence keyData = new ASN1Sequence();

	// encode <m>
	keyData.add(new ASN1Integer(m));
	// encode <k>
	keyData.add(new ASN1Integer(k));
	// encode <field>
	keyData.add(new ASN1OctetString(field.getEncoded()));
	// encode <goppaPoly>
	keyData.add(new ASN1OctetString(gp.getEncoded()));
	// encode <sInv>
	keyData.add(new ASN1OctetString(s.getEncoded()));
	// encode <p>
	keyData.add(new ASN1OctetString(p.getEncoded()));
	// encode <qInv>
	ASN1Sequence qInvSeq = new ASN1Sequence(qInv.length);
	for (int i = 0; i < qInv.length; i++) {
	    qInvSeq.add(new ASN1OctetString(qInv[i].getEncoded()));
	}
	keyData.add(qInvSeq);

	return ASN1Tools.derEncode(keyData);
    }

}
