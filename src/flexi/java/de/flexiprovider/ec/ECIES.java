package de.flexiprovider.ec;

import de.flexiprovider.api.KeyAgreement;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.exceptions.InvalidKeySpecException;
import de.flexiprovider.api.exceptions.InvalidParameterSpecException;
import de.flexiprovider.api.keys.Key;
import de.flexiprovider.api.keys.KeyFactory;
import de.flexiprovider.api.keys.KeyPair;
import de.flexiprovider.api.keys.KeyPairGenerator;
import de.flexiprovider.api.keys.PrivateKey;
import de.flexiprovider.api.keys.PublicKey;
import de.flexiprovider.common.ies.IES;
import de.flexiprovider.common.math.ellipticcurves.Point;
import de.flexiprovider.ec.keys.ECKeyFactory;
import de.flexiprovider.ec.keys.ECKeyPairGenerator;
import de.flexiprovider.ec.keys.ECPrivateKey;
import de.flexiprovider.ec.keys.ECPublicKey;
import de.flexiprovider.ec.keys.ECPublicKeySpec;
import de.flexiprovider.ec.parameters.CurveParams;

/**
 * ECIES (Elliptic Curve Integrated Encryption Scheme) extends the basic IES
 * implementation.
 */
public class ECIES extends IES {

    /**
     * @return the name of this cipher
     */
    public String getName() {
	return "ECIES";
    }

    /**
     * Return the key size of the given key object in bits. Checks whether the
     * key object is an instance of <tt>ECPublicKey</tt> or
     * <tt>ECPrivateKey</tt>.
     * 
     * @param key
     *                the key object
     * @return the key size of the given key object.
     * @throws InvalidKeyException
     *                 if key is invalid.
     */
    public int getKeySize(Key key) throws InvalidKeyException {
	if (key instanceof ECPrivateKey) {
	    return ((ECPrivateKey) key).getParams().getQ().bitLength();
	}
	if (key instanceof ECPublicKey) {
	    return ((ECPublicKey) key).getParams().getQ().bitLength();
	}
	throw new InvalidKeyException("unsupported type");
    }

    /**
     * Check whether the given encryption key is an instance of
     * {@link ECPublicKey}. If not, terminate with an
     * {@link InvalidKeyException}. Otherwise, assign the key parameters and
     * return the checked key.
     * 
     * @param key
     *                the key to be checked
     * @return the checked key
     * @throws InvalidKeyException
     *                 if the key is not an instance of {@link ECPublicKey}.
     */
    protected PublicKey checkPubKey(Key key) throws InvalidKeyException {
	// check key
	if (!(key instanceof ECPublicKey)) {
	    throw new InvalidKeyException("unsupported type");
	}
	ECPublicKey ecPubKey = (ECPublicKey) key;
	keyParams = ecPubKey.getParams();

	return ecPubKey;
    }

    /**
     * Check whether the given encryption key is an instance of
     * {@link ECPrivateKey}. If not, terminate with an
     * {@link InvalidKeyException}. Otherwise, assign the key parameters and
     * return the checked key.
     * 
     * @param key
     *                the key to be checked
     * @return the checked key
     * @throws InvalidKeyException
     *                 if the key is not an instance of {@link ECPrivateKey}.
     */
    protected PrivateKey checkPrivKey(Key key) throws InvalidKeyException {
	// check key
	if (!(key instanceof ECPrivateKey)) {
	    throw new InvalidKeyException("unsupported type");
	}
	ECPrivateKey ecPrivKey = (ECPrivateKey) key;
	keyParams = ecPrivKey.getParams();

	return ecPrivKey;
    }

    /**
     * Instantiate and return the key agreement module.
     * 
     * @return the key agreement module
     */
    protected KeyAgreement getKeyAgreement() {
	return new ECSVDPDHC();
    }

    /**
     * Generate an ephemeral key pair. This method is used in case no ephemeral
     * key pair is specified via the parameters during initialization.
     * 
     * @return the generated ephemeral key pair
     */
    protected KeyPair generateEphKeyPair() {
	KeyPairGenerator kpg = new ECKeyPairGenerator();
	try {
	    kpg.initialize(keyParams, random);
	} catch (InvalidAlgorithmParameterException e) {
	    // the parameters have already been checked
	    throw new RuntimeException("internal error");
	}
	return kpg.genKeyPair();
    }

    /**
     * Encode the ephemeral public key.
     * 
     * @param ephPubKey
     *                the ephemeral public key
     * @return the encoded key
     */
    protected byte[] encodeEphPubKey(PublicKey ephPubKey) {
	Point q;
	try {
	    q = ((ECPublicKey) ephPubKey).getW();
	} catch (InvalidKeyException e) {
	    // the point is correctly initialized with parameters
	    throw new RuntimeException("internal error");
	}
	return q.EC2OSP(Point.ENCODING_TYPE_COMPRESSED);
    }

    /**
     * Compute and return the size (in bytes) of the encoded ephemeral public
     * key.
     * 
     * @return the size of the encoded ephemeral public key
     */
    protected int getEncEphPubKeySize() {
	Point g = ((CurveParams) keyParams).getG();
	return g.EC2OSP(Point.ENCODING_TYPE_COMPRESSED).length;
    }

    /**
     * Decode the ephemeral public key.
     * 
     * @param encEphPubKey
     *                the encoded ephemeral public key
     * @return the decoded key
     */
    protected PublicKey decodeEphPubKey(byte[] encEphPubKey) {

	try {
	    ECPublicKeySpec ecPubKeySpec = new ECPublicKeySpec(encEphPubKey,
		    (CurveParams) keyParams);

	    KeyFactory kf = new ECKeyFactory();
	    return kf.generatePublic(ecPubKeySpec);
	} catch (InvalidParameterSpecException e) {
	    throw new RuntimeException("InvalidParameterSpecException: "
		    + e.getMessage());
	} catch (InvalidKeySpecException e) {
	    throw new RuntimeException("InvalidKeySpecException: "
		    + e.getMessage());
	}
    }

}
