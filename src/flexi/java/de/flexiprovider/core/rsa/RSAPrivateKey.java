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
 * This class implements the <tt>RSAPrivateKey</tt> interface. It represents a
 * RSA private key and is usually instantiated from <tt>RSAKeyPairGenerator</tt>.
 * 
 * @author Thomas Wahrenbruch
 * @author Ralf-Philipp Weinmann
 * @see de.flexiprovider.core.rsa.RSAKeyPairGenerator
 */
public class RSAPrivateKey extends
	de.flexiprovider.core.rsa.interfaces.RSAPrivateKey {

    /**
     * The number n = p*q.
     * 
     * @serial
     */
    private FlexiBigInt n;

    /**
     * The private exponent d.
     * 
     * @serial
     */
    private FlexiBigInt d;

    /**
     * Construct a new private RSA key.
     * 
     * @param n -
     *                the modulus n = p*q
     * @param d -
     *                the private exponent d
     * @see de.flexiprovider.core.rsa.RSAKeyPairGenerator
     */
    protected RSAPrivateKey(FlexiBigInt n, FlexiBigInt d) {
	this.n = n;
	this.d = d;
    }

    /**
     * Construct an RSAPrivKey out of the given key specification.
     * 
     * @param keySpec
     *                the key specification
     */
    protected RSAPrivateKey(RSAPrivateKeySpec keySpec) {
	this(keySpec.getN(), keySpec.getD());
    }

    /**
     * @return the modulus n
     */
    public FlexiBigInt getN() {
	return n;
    }

    /**
     * @return the private exponent d
     */
    public FlexiBigInt getD() {
	return d;
    }

    /**
     * Compare this key with another object
     * 
     * @param other
     *                the other object
     * @return the result of the comparison
     */
    public boolean equals(Object other) {
	if (other == null || !(other instanceof RSAPrivateKey)) {
	    return false;
	}

	RSAPrivateKey otherKey = (RSAPrivateKey) other;

	if (n.equals(otherKey.n) && d.equals(otherKey.d)) {
	    return true;
	}

	return false;
    }

    public int hashCode() {
	return n.hashCode() + d.hashCode();
    }

    /**
     * @return a human readable form of the key
     */
    public String toString() {
	return "n = 0x" + n.toString(16) + "\n" + "d = 0x" + d.toString(16)
		+ "\n";
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
	keyData.add(ASN1Tools.createInteger(d));
	return ASN1Tools.derEncode(keyData);
    }

}
