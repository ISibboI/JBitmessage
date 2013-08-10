/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.rsa;

import codec.asn1.ASN1Null;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1Type;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.util.ASN1Tools;

/**
 * This class implements the <tt>RSAPublicKey</tt> interface. It represents a
 * RSA public key and is usually instantiated from <tt>RSAKeyPairGenerator</tt>.
 * 
 * @author Thomas Wahrenbruch
 * @author Ralf-Philipp Weinmann
 * @see de.flexiprovider.core.rsa.RSAKeyPairGenerator
 */
public final class RSAPublicKey extends
	de.flexiprovider.core.rsa.interfaces.RSAPublicKey {

    /**
     * The number n = p*q.
     */
    private FlexiBigInt n;

    /**
     * The public exponent e.
     */
    private FlexiBigInt e;

    /**
     * Generates a new RSA public key.
     * 
     * @param n
     *                the modulus n = p*q;
     * @param e
     *                the public exponent e.
     * @see de.flexiprovider.core.rsa.RSAKeyPairGenerator
     */
    public RSAPublicKey(FlexiBigInt n, FlexiBigInt e) {
	this.n = n;
	this.e = e;
    }

    /**
     * Construct an RSAPubKey out of the given key specification.
     * 
     * @param keySpec
     *                the key specification
     */
    public RSAPublicKey(RSAPublicKeySpec keySpec) {
	this(keySpec.getN(), keySpec.getE());
    }

    /**
     * @return the modulus n
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
     * @return a human readable form of the key
     */
    public String toString() {
	String result;
	result = "modulus n = 0x" + n.toString(16) + "\n";
	result += "public exponent e = 0x" + e.toString(16);
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
	if (other == null || !(other instanceof RSAPublicKey)) {
	    return false;
	}

	RSAPublicKey otherKey = (RSAPublicKey) other;

	if (n.equals(otherKey.n) && e.equals(otherKey.e)) {
	    return true;
	}

	return false;
    }

    public int hashCode() {
	return n.hashCode() + e.hashCode();
    }

    /**
     * @return the OID to encode in the SubjectPublicKeyInfo structure
     */
    protected ASN1ObjectIdentifier getOID() {
	return new ASN1ObjectIdentifier(RSAKeyFactory.OID);
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
	keyData.add(ASN1Tools.createInteger(n));
	keyData.add(ASN1Tools.createInteger(e));
	return ASN1Tools.derEncode(keyData);
    }

}
