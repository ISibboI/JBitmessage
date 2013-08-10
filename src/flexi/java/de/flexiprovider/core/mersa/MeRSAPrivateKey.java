/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.mersa;

import codec.asn1.ASN1Integer;
import codec.asn1.ASN1Null;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1Type;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.util.ASN1Tools;
import de.flexiprovider.core.rsa.RSAPrivateCrtKey;

/**
 * This class implements the MeRSAPrivateKey interface.
 * 
 * @author Erik Dahmen
 * @author Paul Nguentcheu
 * @see de.flexiprovider.core.mersa.MeRSAKeyPairGenerator
 */
public class MeRSAPrivateKey extends RSAPrivateCrtKey {

    /**
     * The exponent k.
     */
    private FlexiBigInt k;

    /**
     * The number e<sup><font size="-2">-1</font></sup> mod p.
     */
    private FlexiBigInt eInvP;

    /**
     * Generate a new MeRSA private key.
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
     *                the coefficient for MeRSA decryption with the CRT.
     * @param k
     *                the exponent k.
     * @param eInvP
     *                the inverse of the public exponent modulo p.
     * @see MeRSAKeyPairGenerator
     */
    protected MeRSAPrivateKey(FlexiBigInt n, FlexiBigInt e, FlexiBigInt d,
	    FlexiBigInt p, FlexiBigInt q, FlexiBigInt dP, FlexiBigInt dQ,
	    FlexiBigInt crtCoeff, FlexiBigInt k, FlexiBigInt eInvP) {
	super(n, e, d, p, q, dP, dQ, crtCoeff);
	this.eInvP = eInvP;
	this.crtCoeff = crtCoeff;
    }

    /**
     * Construct an MeRSAPrivateKey out of the given key specification.
     * 
     * @param keySpec
     *                the key specification
     */
    protected MeRSAPrivateKey(MeRSAPrivateKeySpec keySpec) {
	this(keySpec.getN(), keySpec.getE(), keySpec.getD(), keySpec.getP(),
		keySpec.getQ(), keySpec.getDp(), keySpec.getDq(), keySpec
			.getCRTCoeff(), keySpec.getK(), keySpec.getEInvP());
    }

    /**
     * @return the exponent k
     */
    public FlexiBigInt getK() {
	return k;
    }

    /**
     * @return the inverse of the public exponent modulo p
     */
    public FlexiBigInt getEInvP() {
	return eInvP;
    }

    /**
     * Compare this key with another object.
     * 
     * @param other
     *                the other object
     * @return the result of the comparison
     */
    public boolean equals(Object other) {
	if (other == null || !(other instanceof MeRSAPrivateKey)) {
	    return false;
	}

	MeRSAPrivateKey otherKey = (MeRSAPrivateKey) other;

	if (n.equals(otherKey.n) && p.equals(otherKey.p)
		&& q.equals(otherKey.q) && d.equals(otherKey.d)
		&& e.equals(otherKey.e) && dP.equals(otherKey.dP)
		&& dQ.equals(otherKey.dQ) && k.equals(otherKey.k)
		&& eInvP.equals(otherKey.eInvP)
		&& crtCoeff.equals(otherKey.crtCoeff)) {
	    return true;
	}

	return false;
    }

    /**
     * @return a human readable form of the key
     */
    public String toString() {
	String out = "";
	out += "modulus n:            0x" + n.toString(16) + "\n";
	out += "public exponent e:    0x" + e.toString(16) + "\n";
	out += "exponent k:           0x" + k.toString(16) + "\n";
	out += "private exponent d:   0x" + d.toString(16) + "\n";
	out += "prime P:              0x" + p.toString(16) + "\n";
	out += "prime Q:              0x" + q.toString(16) + "\n";
	out += "prime exponent P:     0x" + dP.toString(16) + "\n";
	out += "prime exponent Q:     0x" + dQ.toString(16) + "\n";
	out += "inverse of e mod p:   0x" + dQ.toString(16) + "\n";
	out += "crt coefficient:      0x" + crtCoeff.toString(16) + "\n";
	return out;
    }

    public int hashCode() {
	return n.hashCode() + e.hashCode() + k.hashCode() + d.hashCode()
		+ p.hashCode() + q.hashCode() + dP.hashCode() + dQ.hashCode()
		+ eInvP.hashCode() + +crtCoeff.hashCode();

    }

    /**
     * @return the OID to encode in the SubjectPublicKeyInfo structure
     */
    protected ASN1ObjectIdentifier getOID() {
	// TODO assign correct OID
	return new ASN1ObjectIdentifier();
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
	keyData.add(ASN1Tools.createInteger(k));
	keyData.add(ASN1Tools.createInteger(d));
	keyData.add(ASN1Tools.createInteger(p));
	keyData.add(ASN1Tools.createInteger(q));
	keyData.add(ASN1Tools.createInteger(dP));
	keyData.add(ASN1Tools.createInteger(dQ));
	keyData.add(ASN1Tools.createInteger(eInvP));
	keyData.add(ASN1Tools.createInteger(crtCoeff));
	return ASN1Tools.derEncode(keyData);
    }

}
