/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.rsa;

import codec.asn1.ASN1Integer;
import codec.asn1.ASN1Null;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1Type;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.util.ASN1Tools;

/**
 * This class implements the RSAPrivateCrtKey interface. It represents a RSA
 * private key with additional information (for the RSA decryption with the CRT)
 * and is usually instantiated from RSAKeyPairGenerator.
 * 
 * @author Thomas Wahrenbruch
 * @see de.flexiprovider.core.rsa.RSAKeyPairGenerator
 */
public class RSAPrivateCrtKey extends
	de.flexiprovider.core.rsa.interfaces.RSAPrivateCrtKey {

    /**
     * The RSA algorithm identifier.
     */
    private static final String RSA_OID_STRING = "1.2.840.113549.1.1.1";

    /**
     * The number n = p*q.
     */
    protected FlexiBigInt n;

    /**
     * The private exponent d.
     */
    protected FlexiBigInt d;

    /**
     * The public exponent e.
     */
    protected FlexiBigInt e;

    /**
     * The prime p.
     */
    protected FlexiBigInt p;

    /**
     * The prime q.
     */
    protected FlexiBigInt q;

    /**
     * The number d mod (p-1).
     */
    protected FlexiBigInt dP;

    /**
     * The number d mod (q-1).
     */
    protected FlexiBigInt dQ;

    /**
     * The CRT coefficient q<sup><font size="-2">-1</font></sup> mod p.
     */
    protected FlexiBigInt crtCoeff;

    /**
     * Generate a new RSA private key.
     * 
     * @param n
     *                the number n = p*q;
     * @param e
     *                the public exponent e.
     * @param d
     *                the private exponent d.
     * @param p
     *                the prime p.
     * @param q
     *                the prime q.
     * @param dP
     *                the number d mod (p-1).
     * @param dQ
     *                the number d mod (q-1).
     * @param crtCoeff
     *                the coefficient for RSA decryption with the CRT.
     * @see de.flexiprovider.core.rsa.RSAKeyPairGenerator
     */
    public RSAPrivateCrtKey(FlexiBigInt n, FlexiBigInt e, FlexiBigInt d,
	    FlexiBigInt p, FlexiBigInt q, FlexiBigInt dP, FlexiBigInt dQ,
	    FlexiBigInt crtCoeff) {
	this.n = n;
	this.d = d;
	this.e = e;
	this.p = p;
	this.q = q;
	this.dP = dP;
	this.dQ = dQ;
	this.crtCoeff = crtCoeff;
    }

    /**
     * Construct an RSAPrivCrtKey out of the given key specification.
     * 
     * @param keySpec
     *                the key specification
     */
    protected RSAPrivateCrtKey(RSAPrivateCrtKeySpec keySpec) {
	this(keySpec.getN(), keySpec.getE(), keySpec.getD(), keySpec.getP(),
		keySpec.getQ(), keySpec.getDp(), keySpec.getDq(), keySpec
			.getCRTCoeff());
    }

    /**
     * @return the n n
     */
    public FlexiBigInt getN() {
	return n;
    }

    /**
     * @return the public exponent e
     */
    public FlexiBigInt getE() {
	return e;
    }

    /**
     * @return the private exponent d
     */
    public FlexiBigInt getD() {
	return d;
    }

    /**
     * @return the prime p
     */
    public FlexiBigInt getP() {
	return p;
    }

    /**
     * @return the prime q
     */
    public FlexiBigInt getQ() {
	return q;
    }

    /**
     * @return the private exponent d mod (p-1)
     */
    public FlexiBigInt getDp() {
	return dP;
    }

    /**
     * @return the private exponent d mod (q-1)
     */
    public FlexiBigInt getDq() {
	return dQ;
    }

    /**
     * @return the CRT coefficient
     */
    public FlexiBigInt getCRTCoeff() {
	return crtCoeff;
    }

    /**
     * Compare this key with another object.
     * 
     * @param other
     *                the other object
     * @return the result of the comparison
     */
    public boolean equals(Object other) {
	if (other == null || !(other instanceof RSAPrivateCrtKey)) {
	    return false;
	}

	RSAPrivateCrtKey otherKey = (RSAPrivateCrtKey) other;

	if (n.equals(otherKey.n) && p.equals(otherKey.p)
		&& q.equals(otherKey.q) && d.equals(otherKey.d)
		&& e.equals(otherKey.e) && dP.equals(otherKey.dP)
		&& dQ.equals(otherKey.dQ) && crtCoeff.equals(otherKey.crtCoeff)) {
	    return true;
	}

	return false;
    }

    /**
     * @return a human readable form of the key
     */
    public String toString() {
	String out = "";
	out += "modulus n:          0x" + n.toString(16) + "\n";
	out += "public exponent e:  0x" + e.toString(16) + "\n";
	out += "private exponent d: 0x" + d.toString(16) + "\n";
	out += "prime P:            0x" + p.toString(16) + "\n";
	out += "prime Q:            0x" + q.toString(16) + "\n";
	out += "prime exponent P:   0x" + dP.toString(16) + "\n";
	out += "prime exponent Q:   0x" + dQ.toString(16) + "\n";
	out += "crt coefficient:    0x" + crtCoeff.toString(16) + "\n";
	return out;
    }

    public int hashCode() {
	return n.hashCode() + d.hashCode() + e.hashCode() + p.hashCode()
		+ q.hashCode() + dP.hashCode() + dQ.hashCode()
		+ crtCoeff.hashCode();

    }

    /**
     * @return the OID to encode in the SubjectPublicKeyInfo structure
     */
    protected ASN1ObjectIdentifier getOID() {
	return new ASN1ObjectIdentifier(RSA_OID_STRING);
    }

    /**
     * @return the algorithm parameters to encode in the SubjectPublicKeyInfo
     *         structure
     */
    protected ASN1Type getAlgParams() {
	return new ASN1Null();
    }

    /**
     * @return the keyData to encode in the SubjectPublicKeyInfo structure
     */
    protected byte[] getKeyData() {
	ASN1Sequence keyData = new ASN1Sequence();
	keyData.add(new ASN1Integer(0));
	keyData.add(ASN1Tools.createInteger(n));
	keyData.add(ASN1Tools.createInteger(e));
	keyData.add(ASN1Tools.createInteger(d));
	keyData.add(ASN1Tools.createInteger(p));
	keyData.add(ASN1Tools.createInteger(q));
	keyData.add(ASN1Tools.createInteger(dP));
	keyData.add(ASN1Tools.createInteger(dQ));
	keyData.add(ASN1Tools.createInteger(crtCoeff));
	return ASN1Tools.derEncode(keyData);
    }

}
