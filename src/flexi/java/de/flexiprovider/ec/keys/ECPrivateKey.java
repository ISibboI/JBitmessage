/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.ec.keys;

import codec.asn1.ASN1Integer;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1OctetString;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1Type;
import de.flexiprovider.api.exceptions.InvalidParameterSpecException;
import de.flexiprovider.api.keys.PrivateKey;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.util.ASN1Tools;
import de.flexiprovider.ec.parameters.CurveParams;
import de.flexiprovider.ec.parameters.ECParameters;

/**
 * The interface to an EC <i>private key</i>. The private key is an integer
 * <i>s</i> in the range [1, r - 1], where <i>r</i> is a prime and part of the
 * DomainParameters (see {@link CurveParams}).
 * 
 * @see ECPublicKey
 * @author Birgit Henhapl
 * @author Michele Boivin
 */
public class ECPrivateKey extends PrivateKey {

    // the private key s, 1 < s < r.
    private FlexiBigInt mS;

    // the EC domain parameters
    private CurveParams mParams;

    /**
     * Inner class providing the ECDSA ASN.1 private key structure.
     * <p>
     * The ASN.1 definition of the key structure is
     * 
     * <pre>
     *  ASN1ECPrivateKey ::= SEQUENCE {
     *   version        INTEGER,              -- this version is 1
     *   privateKey     OCTET STRING,
     *   parameters [0] Parameters OPTIONAL,
     *   publicKey  [1] BITSTRING OPTIONAL
     * }
     * </pre>
     */
    private static class ECASN1PrivateKey extends ASN1Sequence {

	private ASN1Integer version;

	private ASN1OctetString privKey;

	public ECASN1PrivateKey(int version, ASN1OctetString privKey) {
	    super(2);
	    this.version = new ASN1Integer(version);
	    this.privKey = privKey;
	    add(this.version);
	    add(privKey);
	}

	public ASN1OctetString getPrivateKey() {
	    return privKey;
	}
    }

    /**
     * Generate a new ECPrivateKey with the specified parameters.
     * 
     * @param s
     *                the FlexiBigInt that represents the private key
     * @param params
     *                the parameters
     */
    protected ECPrivateKey(FlexiBigInt s, CurveParams params) {
	mS = s;
	mParams = params;
    }

    /**
     * Construct an ECPrivateKey out of the given key specification.
     * 
     * @param keySpec
     *                the key specification
     */
    protected ECPrivateKey(ECPrivateKeySpec keySpec) {
	this(keySpec.getS(), keySpec.getParams());
    }

    /**
     * @return the private key s
     */
    public FlexiBigInt getS() {
	return mS;
    }

    /**
     * @return the name of the algorithm
     */
    public String getAlgorithm() {
	return "EC";
    }

    /**
     * This method returns this private key s with its corresponding
     * ECParameterSpec as String. The format is:<br>
     * s = ...<br>
     * q = ...<br>
     * a = ...<br>
     * b = ...<br>
     * G = (x<sub>G</sub>, y<sub>G</sub>)<br>
     * r = ...<br>
     * k = ...<br>
     * 
     * @return the private key and its corresponding ecparameters as String
     * @see CurveParams
     */
    public String toString() {
	return "s = " + mS.toString(16) + "\n" + mParams.toString();
    }

    /**
     * Returns the corresponding ecdomain parameters.
     * 
     * @return the corresponding ecdomain parameters.
     */
    public CurveParams getParams() {
	return mParams;
    }

    /**
     * Compare this private key with another object.
     * 
     * @param obj
     *                another object
     * @return the result of the comparison
     */
    public boolean equals(Object obj) {
	if (obj == null || !(obj instanceof ECPrivateKey)) {
	    return false;
	}

	ECPrivateKey oKey = (ECPrivateKey) obj;
	boolean value = oKey.mS.equals(mS);
	value &= mParams.equals(oKey.mParams);

	return value;
    }

    public int hashCode() {
	return mS.hashCode() + mParams.getR().hashCode()
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
	byte[] keyBytes = mS.toByteArray();
	ECASN1PrivateKey keyData = new ECASN1PrivateKey(1, new ASN1OctetString(
		keyBytes));
	return ASN1Tools.derEncode(keyData);
    }

}
