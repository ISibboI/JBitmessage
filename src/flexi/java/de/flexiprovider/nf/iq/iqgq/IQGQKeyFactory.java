package de.flexiprovider.nf.iq.iqgq;

import codec.CorruptedCodeException;
import codec.asn1.ASN1Integer;
import codec.asn1.ASN1OctetString;
import codec.asn1.ASN1Sequence;
import codec.pkcs8.PrivateKeyInfo;
import codec.x509.SubjectPublicKeyInfo;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.exceptions.InvalidKeySpecException;
import de.flexiprovider.api.exceptions.InvalidParameterSpecException;
import de.flexiprovider.api.exceptions.NoSuchAlgorithmException;
import de.flexiprovider.api.keys.Key;
import de.flexiprovider.api.keys.KeyFactory;
import de.flexiprovider.api.keys.KeySpec;
import de.flexiprovider.api.keys.PrivateKey;
import de.flexiprovider.api.keys.PublicKey;
import de.flexiprovider.api.parameters.AlgorithmParameters;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.math.quadraticfields.IQEncodingException;
import de.flexiprovider.common.math.quadraticfields.QuadraticIdeal;
import de.flexiprovider.common.util.ASN1Tools;
import de.flexiprovider.pki.AlgorithmIdentifier;
import de.flexiprovider.pki.PKCS8EncodedKeySpec;
import de.flexiprovider.pki.PKITools;
import de.flexiprovider.pki.X509EncodedKeySpec;

/**
 * This class provides the translation between key specifications ({@link IQGQPrivateKeySpec}
 * or {@link IQGQPublicKeySpec}), DER-encoded ASN.1 representations ({@link X509EncodedKeySpec}
 * or {@link PKCS8EncodedKeySpec}), and keys ({@link IQGQPrivateKey} or
 * {@link IQGQPublicKey}).
 * 
 * @author Birgit Henhapl
 * @author Michele Boivin
 * @author Ralf-P. Weinmann
 */
public class IQGQKeyFactory extends KeyFactory {

    /**
     * The OID of the IQGQ key representation.
     */
    public static final String OID = "1.3.6.1.4.1.8301.3.1.1.4";

    /**
     * Generates a private key object from the provided key specification (key
     * material).
     * 
     * @param keySpec
     *                the specification (key material) of the private key
     * @return the private key
     * @throws InvalidKeySpecException
     *                 if the given key specification is inappropriate for this
     *                 key factory to produce a private key.
     */
    public PrivateKey generatePrivate(KeySpec keySpec)
	    throws InvalidKeySpecException {

	if (keySpec instanceof IQGQPrivateKeySpec) {
	    return new IQGQPrivateKey((IQGQPrivateKeySpec) keySpec);
	}

	if (keySpec instanceof PKCS8EncodedKeySpec) {
	    // extract DER-encoded key
	    byte[] encKey = ((PKCS8EncodedKeySpec) keySpec).getEncoded();

	    // decode the PKCS#8 data structure to the pki object
	    PrivateKeyInfo pki = new PrivateKeyInfo();
	    try {
		ASN1Tools.derDecode(encKey, pki);
	    } catch (Exception ce) {
		throw new InvalidKeySpecException(
			"Unable to decode PKCS8EncodedKeySpec.");
	    }

	    AlgorithmIdentifier aid = PKITools.getAlgorithmIdentifier(pki);
	    IQGQParameterSpec iqgqParams;
	    try {
		AlgorithmParameters params = aid.getParams();
		iqgqParams = (IQGQParameterSpec) params
			.getParameterSpec(IQGQParameterSpec.class);
	    } catch (NoSuchAlgorithmException e) {
		throw new InvalidKeySpecException("NoSuchAlgorithmException: "
			+ e.getMessage());
	    } catch (InvalidAlgorithmParameterException e) {
		throw new InvalidKeySpecException(
			"InvalidAlgorithmParameterException: " + e.getMessage());
	    } catch (InvalidParameterSpecException e) {
		throw new InvalidKeySpecException(
			"InvalidParameterSpecException: " + e.getMessage());
	    }

	    ASN1Sequence privKeySequence;
	    try {
		privKeySequence = (ASN1Sequence) pki.getDecodedRawKey();
	    } catch (CorruptedCodeException cce) {
		throw new InvalidKeySpecException("CorruptedCodeException: "
			+ cce.getMessage());
	    }

	    byte[] encTheta = ((ASN1OctetString) privKeySequence.get(0))
		    .getByteArray();
	    FlexiBigInt exponent = ASN1Tools
		    .getFlexiBigInt((ASN1Integer) privKeySequence.get(1));
	    FlexiBigInt discriminant = iqgqParams.getDiscriminant();

	    QuadraticIdeal theta;
	    try {
		theta = QuadraticIdeal.octetsToIdeal(discriminant, encTheta);
	    } catch (IQEncodingException iqee) {
		throw new InvalidKeySpecException("CorruptedCodeException: "
			+ iqee.getMessage());
	    }

	    return new IQGQPrivateKey(iqgqParams, theta, exponent);
	}

	throw new InvalidKeySpecException("unsupported type");
    }

    /**
     * Generates a public key object from the provided key specification (key
     * material).
     * 
     * @param keySpec
     *                the specification (key material) of the public key
     * @return the public key
     * @throws InvalidKeySpecException
     *                 if the given key specification is inappropriate for this
     *                 key factory to produce a public key.
     */
    public PublicKey generatePublic(KeySpec keySpec)

    throws InvalidKeySpecException {
	if (keySpec instanceof IQGQPublicKeySpec) {
	    return new IQGQPublicKey((IQGQPublicKeySpec) keySpec);
	}

	if (keySpec instanceof X509EncodedKeySpec) {
	    // extract DER-encoded key
	    byte[] encKey = ((X509EncodedKeySpec) keySpec).getEncoded();

	    // decode the X.509 data structure to the spki object
	    SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo();
	    try {
		ASN1Tools.derDecode(encKey, spki);
	    } catch (Exception ce) {
		throw new InvalidKeySpecException(
			"Unable to decode X509EncodedKeySpec.");
	    }

	    AlgorithmIdentifier aid = PKITools.getAlgorithmIdentifier(spki);
	    IQGQParameterSpec iqgqParams;
	    try {
		AlgorithmParameters params = aid.getParams();
		iqgqParams = (IQGQParameterSpec) params
			.getParameterSpec(IQGQParameterSpec.class);
	    } catch (NoSuchAlgorithmException e) {
		throw new InvalidKeySpecException("NoSuchAlgorithmException: "
			+ e.getMessage());
	    } catch (InvalidAlgorithmParameterException e) {
		throw new InvalidKeySpecException(
			"InvalidAlgorithmParameterException: " + e.getMessage());
	    } catch (InvalidParameterSpecException e) {
		throw new InvalidKeySpecException(
			"InvalidParameterSpecException: " + e.getMessage());
	    }

	    FlexiBigInt discriminant = iqgqParams.getDiscriminant();

	    ASN1Sequence pubKeySequence;
	    try {
		pubKeySequence = (ASN1Sequence) spki.getDecodedRawKey();
	    } catch (CorruptedCodeException cce) {
		throw new InvalidKeySpecException("CorruptedCodeException: "
			+ cce.getMessage());
	    }

	    byte[] encAlpha = ((ASN1OctetString) pubKeySequence.get(0))
		    .getByteArray();
	    FlexiBigInt exponent = ASN1Tools
		    .getFlexiBigInt((ASN1Integer) pubKeySequence.get(1));

	    QuadraticIdeal alpha;
	    try {
		alpha = QuadraticIdeal.octetsToIdeal(discriminant, encAlpha);
	    } catch (IQEncodingException iqee) {
		throw new InvalidKeySpecException("CorruptedCodeException: "
			+ iqee.getMessage());
	    }

	    return new IQGQPublicKey(iqgqParams, alpha, exponent);
	}

	throw new InvalidKeySpecException("unsupported type");
    }

    /**
     * Returns a specification (key material) of the given key object.
     * <tt>keySpec</tt> identifies the specification class in which the key
     * material should be returned. It could, for example, be
     * <tt>IQGQPublicKeySpec.class</tt>, to indicate that the key material
     * should be returned in an instance of the <tt>IQGQPublicKeySpec</tt>
     * class.
     * 
     * @param key
     *                the key
     * @param keySpec
     *                the specification class in which the key material should
     *                be returned
     * @return the underlying key specification (key material) in an instance of
     *         the requested specification class
     * @throws InvalidKeySpecException
     *                 if the requested key specification is inappropriate for
     *                 the given key, or the given key cannot be dealt with
     *                 (e.g., the given key has an unrecognized format).
     */
    public KeySpec getKeySpec(Key key, Class keySpec)
	    throws InvalidKeySpecException {

	if (key instanceof IQGQPublicKey) {
	    if (!keySpec.isAssignableFrom(IQGQPublicKeySpec.class)) {
		throw new InvalidKeySpecException("unsupported spec type");
	    }
	    IQGQPublicKey pubKey = (IQGQPublicKey) key;
	    return new IQGQPublicKeySpec(pubKey.getParams(), pubKey.getAlpha(),
		    pubKey.getExponent());
	}

	if (key instanceof IQGQPrivateKey) {
	    if (!keySpec.isAssignableFrom(IQGQPrivateKeySpec.class)) {
		throw new InvalidKeySpecException("unsupported spec type");
	    }
	    IQGQPrivateKey privKey = (IQGQPrivateKey) key;
	    return new IQGQPrivateKeySpec(privKey.getParams(), privKey
		    .getTheta(), privKey.getExponent());
	}

	throw new InvalidKeySpecException("unsupported key type");
    }

    /**
     * Translates a key object, whose provider may be unknown or potentially
     * untrusted, into a corresponding key object of this key factory.
     * Currently, only the following key types are supported:
     * {@link IQGQPublicKey}, {@link IQGQPrivateKey}.
     * 
     * @param key
     *                the key whose provider is unknown or untrusted
     * @return the translated key
     * @throws InvalidKeyException
     *                 if the given key cannot be processed by this key factory.
     */
    public Key translateKey(Key key) throws InvalidKeyException {
	if ((key instanceof IQGQPublicKey) || (key instanceof IQGQPrivateKey)) {
	    return key;
	}
	throw new InvalidKeyException("unsupported type");
    }

}
