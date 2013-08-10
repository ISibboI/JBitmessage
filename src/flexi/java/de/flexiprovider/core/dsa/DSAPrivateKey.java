/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.dsa;

import codec.asn1.ASN1Integer;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1Type;
import de.flexiprovider.api.exceptions.InvalidParameterSpecException;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.util.ASN1Tools;
import de.flexiprovider.core.dsa.interfaces.DSAParams;

/**
 * This class implements the DSAPrivateKey interface.
 * 
 * @author Thomas Wahrenbruch
 */
public class DSAPrivateKey extends
	de.flexiprovider.core.dsa.interfaces.DSAPrivateKey {

    /**
     * The secret exponent x
     */
    private FlexiBigInt x;

    /**
     * The normal DSA parameters.
     */
    private DSAParams params;

    /**
     * Construct a DSA private key with the specified parameters (used by the
     * {@link DSAKeyPairGenerator}).
     * 
     * @param x
     *                the secret exponent.
     * @param params
     *                the DSA parameters.
     */
    protected DSAPrivateKey(FlexiBigInt x, DSAParams params) {
	this.x = x;
	this.params = params;
    }

    /**
     * Construct a DSA private key from the given key specification (used by the
     * {@link DSAKeyFactory}).
     * 
     * @param keySpec
     *                the key specification
     */
    protected DSAPrivateKey(DSAPrivateKeySpec keySpec) {
	this(keySpec.getValueX(), new DSAParameterSpec(keySpec.getPrimeP(),
		keySpec.getPrimeQ(), keySpec.getBaseG()));

    }

    /**
     * This function returns the name of the corresponding algorithm "DSA".
     * 
     * @return "DSA".
     */
    public String getAlgorithm() {
	return "DSA";
    }

    /**
     * This function returns the DSA parameters.
     * 
     * @return the DSA parameters.
     */
    public DSAParams getParameters() {
	return params;
    }

    /**
     * This function returns the secret exponent x.
     * 
     * @return the secret exponent x.
     */
    public FlexiBigInt getValueX() {
	return x;
    }

    /**
     * Returns a human readable form of the key.
     * 
     * @return a human readable form of the key.
     */
    public String toString() {

	String out = "private x: 0x" + x.toString(16) + "\n" + "p:         0x"
		+ params.getPrimeP().toString(16) + "\n" + "q:         0x"
		+ params.getPrimeQ().toString(16) + "\n" + "g:         0x"
		+ params.getBaseG().toString(16) + "\n";

	return out;
    }

    public boolean equals(Object obj) {
	if (obj == null || !(obj instanceof DSAPrivateKey)) {
	    return false;
	}

	DSAPrivateKey otherKey = (DSAPrivateKey) obj;

	boolean value = x.equals(otherKey.x);
	value &= params.getBaseG().equals(otherKey.params.getBaseG());
	value &= params.getPrimeP().equals(otherKey.params.getPrimeP());
	value &= params.getPrimeQ().equals(otherKey.params.getPrimeQ());

	return value;
    }

    public int hashCode() {
	return x.hashCode() + params.getBaseG().hashCode()
		+ params.getPrimeP().hashCode() + params.getPrimeQ().hashCode();
    }

    /**
     * @return the OID to encode in the SubjectPublicKeyInfo structure
     */
    protected ASN1ObjectIdentifier getOID() {
	return new ASN1ObjectIdentifier(DSAKeyFactory.OID);
    }

    /**
     * @return the algorithm parameters to encode in the SubjectPublicKeyInfo
     *         structure
     */
    protected ASN1Type getAlgParams() {
	DSAParameters dsaParams = new DSAParameters();
	DSAParameterSpec dsaParamSpec = new DSAParameterSpec(
		params.getPrimeP(), params.getPrimeQ(), params.getBaseG());
	try {
	    dsaParams.init(dsaParamSpec);
	} catch (InvalidParameterSpecException e) {
	    // the parameters are correct and must be accepted
	    throw new RuntimeException("internal error");
	}
	return dsaParams.getASN1Parameters();
    }

    /**
     * @return the keyData to encode in the SubjectPublicKeyInfo structure
     */
    protected byte[] getKeyData() {
	ASN1Integer keyData = new ASN1Integer(x.toByteArray());
	return ASN1Tools.derEncode(keyData);
    }

}
