/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.ec.keys;

import codec.asn1.ASN1Null;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1Type;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.exceptions.InvalidParameterSpecException;
import de.flexiprovider.api.keys.PublicKey;
import de.flexiprovider.common.math.ellipticcurves.Point;
import de.flexiprovider.common.util.ByteUtils;
import de.flexiprovider.ec.parameters.CurveParams;
import de.flexiprovider.ec.parameters.ECParameters;

/**
 * The interface to a EC <i>public key</i>. The public key is a point <i>W</i>,
 * built by <nobr><i>W = sG</i></nobr>, where <i>G</i> is generator of a
 * subgroup with order <i>r</i>, and where <i>s</i> is the <i>private key</i>,
 * an integer in the range [1, r - 1].
 * 
 * @see de.flexiprovider.ec.keys.ECPrivateKey
 * @see CurveParams
 * @see de.flexiprovider.common.math.ellipticcurves.Point
 * @author Birgit Henhapl
 * @author Michele Boivin
 */
public class ECPublicKey extends PublicKey {

    // the public key value w := s * G, 1 < s < r
    private Point mW;

    // the encoded public key w in case no EC domain parameters were
    // available at construction time
    private byte[] mEncodedW;

    // the EC domain parameters
    private CurveParams mParams;

    /**
     * Generate a new ECPublicKey with the specified parameters.
     * 
     * @param w
     *                the point that represents the public key
     * @param params
     *                the EC domain parameters
     */
    protected ECPublicKey(Point w, CurveParams params) {
	mW = w;
	mParams = params;
    }

    /**
     * Generate a new ECPublicKey out of the byte array encoding.
     * 
     * @param encodedW
     *                the encoded point that represents the public key
     */
    protected ECPublicKey(byte[] encodedW) {
	mEncodedW = encodedW;
    }

    /**
     * @return the public key W
     * @throws InvalidKeyException
     *                 if the key has not been initialized with EC domain
     *                 parameters yet.
     * @see de.flexiprovider.common.math.ellipticcurves.Point
     */
    public Point getW() throws InvalidKeyException {
	if (mW == null) {
	    throw new InvalidKeyException(
		    "No ecdomain parameters defined for the public point");
	}
	return mW;
    }

    /**
     * @return the uncompressed encoding of the public point W
     */
    public byte[] getEncodedW() {
	if (mEncodedW != null) {
	    return mEncodedW;
	}

	return mW.EC2OSP(Point.ENCODING_TYPE_UNCOMPRESSED);
    }

    /**
     * This method returns the corresponding ECParameterSpec.
     * 
     * @return the corresponding ECParameterSpec.
     * @see CurveParams
     */
    public CurveParams getParams() {
	return mParams;
    }

    /**
     * Returns the name of the algorithm.
     * 
     * @return the name of the algorithm.
     */
    public String getAlgorithm() {
	return "EC";
    }

    /**
     * This method returns this public key W with its corresponding
     * ECParameterSpec as String. The format is:<br>
     * W = (x<sub>W</sub>, y<sub>W</sub>)<br>
     * q = ...<br>
     * a = ...<br>
     * b = ...<br>
     * G = (x<sub>G</sub>, y<sub>G</sub>)<br>
     * r = ...<br>
     * k = ...<br>
     * 
     * In case the public point can not be decoded as no parameters are defined,
     * it is printed as hex string with the format: W = (encoded) 0x...
     * 
     * @return the public key and its corresponding EC domain parameters as
     *         String
     * @see CurveParams
     */
    public String toString() {
	StringBuffer result = new StringBuffer();
	if (mEncodedW != null) {
	    result.append("W= (encoded)\n");
	    result.append(ByteUtils.toHexString(mEncodedW, "0x", ""));
	} else {
	    result.append("W =\n" + mW.toString());
	    if (mParams != null) {
		result.append("\n" + mParams.toString());
	    }
	}
	return result.toString();
    }

    /**
     * Compare this public key with another object.
     * 
     * @param other
     *                the other object
     * @return the result of the comparison
     */
    public boolean equals(Object other) {
	if (other == null || !(other instanceof ECPublicKey)) {
	    return false;
	}

	ECPublicKey otherKey = (ECPublicKey) other;

	return ByteUtils.equals(getEncoded(), otherKey.getEncoded());
    }

    /**
     * @return the hash code of this key
     */
    public int hashCode() {
	return mW.hashCode() + mParams.getR().hashCode()
		+ mParams.getQ().hashCode();
    }

    /**
     * @return the OID to encode in the SubjectPublicKeyInfo structure
     */
    protected ASN1ObjectIdentifier getOID() {
	return new ASN1ObjectIdentifier(ECKeyFactory.OID);
    }

    /**
     * @return the algorithm parameters to encode in the SubjectPublicKeyInfo
     *         structure
     */
    protected ASN1Type getAlgParams() {
	if (mParams == null) {
	    // If no parameters are specified, encode NULL.
	    return new ASN1Null();
	}
	// get the OID of the parameters
	ASN1Type algParams = mParams.getOID();
	if (algParams == null) {
	    // If no OID is given, the parameters are specified explicitly. In
	    // this case, use the corresponding AlgorithmParameters class to get
	    // the ASN.1 encoded parameters.
	    ECParameters ecParams = new ECParameters();
	    try {
		ecParams.init(mParams);
	    } catch (InvalidParameterSpecException e) {
		// the parameters are correct and must be accepted
		throw new RuntimeException("internal error");
	    }
	    algParams = ecParams.getASN1Params();
	}
	return algParams;
    }

    /**
     * @return the keyData to encode in the SubjectPublicKeyInfo structure
     */
    protected byte[] getKeyData() {
	byte[] keyBytes;
	if (mEncodedW == null) {
	    keyBytes = mW.EC2OSP(Point.ENCODING_TYPE_UNCOMPRESSED);
	} else {
	    keyBytes = mEncodedW;
	}
	return keyBytes;
    }

}
