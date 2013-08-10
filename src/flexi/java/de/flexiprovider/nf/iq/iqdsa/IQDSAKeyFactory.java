package de.flexiprovider.nf.iq.iqdsa;

import codec.CorruptedCodeException;
import codec.asn1.ASN1Integer;
import codec.asn1.ASN1OctetString;
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
 * This class provides the translation between key specifications ({@link IQDSAPrivateKeySpec}
 * or {@link IQDSAPublicKeySpec}), DER-encoded ASN.1 representations ({@link X509EncodedKeySpec}
 * or {@link PKCS8EncodedKeySpec}), and keys ({@link IQDSAPrivateKey} or
 * {@link IQDSAPublicKey}).
 * 
 * @author Birgit Henhapl
 * @author Michele Boivin
 * @author Ralf-P. Weinmann
 */
public class IQDSAKeyFactory extends KeyFactory {

    /**
     * The OID of the IQDSA key representation.
     */
    public static final String OID = "1.3.6.1.4.1.8301.3.1.1.1";

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

	if (keySpec instanceof IQDSAPrivateKeySpec) {
	    return new IQDSAPrivateKey((IQDSAPrivateKeySpec) keySpec);
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
	    IQDSAParameterSpec iqdsaParams;
	    try {
		AlgorithmParameters params = aid.getParams();
		iqdsaParams = (IQDSAParameterSpec) params
			.getParameterSpec(IQDSAParameterSpec.class);
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

	    FlexiBigInt a;
	    try {
		a = ASN1Tools.getFlexiBigInt((ASN1Integer) pki
			.getDecodedRawKey());
	    } catch (CorruptedCodeException cce) {
		throw new InvalidKeySpecException("CorruptedCodeException: "
			+ cce.getMessage());
	    }

	    return new IQDSAPrivateKey(iqdsaParams, a);
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

	if (keySpec instanceof IQDSAPublicKeySpec) {
	    return new IQDSAPublicKey((IQDSAPublicKeySpec) keySpec);
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
	    IQDSAParameterSpec iqdsaParams;
	    try {
		AlgorithmParameters params = aid.getParams();
		iqdsaParams = (IQDSAParameterSpec) params
			.getParameterSpec(IQDSAParameterSpec.class);
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

	    byte[] encAlpha;
	    try {
		encAlpha = ((ASN1OctetString) spki.getDecodedRawKey())
			.getByteArray();
	    } catch (CorruptedCodeException cce) {
		throw new InvalidKeySpecException("CorruptedCodeException: "
			+ cce.getMessage());
	    }

	    FlexiBigInt discriminant = iqdsaParams.getDiscriminant();

	    QuadraticIdeal alpha;
	    try {
		alpha = QuadraticIdeal.octetsToIdeal(discriminant, encAlpha);
	    } catch (IQEncodingException iqee) {
		throw new InvalidKeySpecException("CorruptedCodeException: "
			+ iqee.getMessage());
	    }

	    return new IQDSAPublicKey(iqdsaParams, alpha);
	}

	throw new InvalidKeySpecException("unsupported type");
    }

    /**
     * Returns a specification (key material) of the given key object.
     * <tt>keySpec</tt> identifies the specification class in which the key
     * material should be returned. It could, for example, be
     * <tt>IQDSAPublicKeySpec.class</tt>, to indicate that the key material
     * should be returned in an instance of the <tt>IQDSAPublicKeySpec</tt>
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

	if (key instanceof IQDSAPublicKey) {
	    if (!keySpec.isAssignableFrom(IQDSAPublicKeySpec.class)) {
		throw new InvalidKeySpecException("unsupported spec type");
	    }
	    IQDSAPublicKey pubKey = (IQDSAPublicKey) key;
	    return new IQDSAPublicKeySpec(pubKey.getParams(), pubKey.getAlpha());
	}

	if (key instanceof IQDSAPrivateKey) {
	    if (!keySpec.isAssignableFrom(IQDSAPrivateKeySpec.class)) {
		throw new InvalidKeySpecException("unsupported spec type");
	    }
	    IQDSAPrivateKey privKey = (IQDSAPrivateKey) key;
	    return new IQDSAPrivateKeySpec(privKey.getParams(), privKey.getA());
	}

	throw new InvalidKeySpecException("unsupported key type");
    }

    /**
     * Translates a key object, whose provider may be unknown or potentially
     * untrusted, into a corresponding key object of this key factory.
     * Currently, only the following key types are supported:
     * {@link IQDSAPublicKey}, {@link IQDSAPrivateKey}.
     * 
     * @param key
     *                the key whose provider is unknown or untrusted
     * @return the translated key
     * @throws InvalidKeyException
     *                 if the given key cannot be processed by this key factory.
     */
    public Key translateKey(Key key) throws InvalidKeyException {
	if ((key instanceof IQDSAPublicKey) || (key instanceof IQDSAPrivateKey)) {
	    return key;
	}
	throw new InvalidKeyException("unsupported type");
    }

}
