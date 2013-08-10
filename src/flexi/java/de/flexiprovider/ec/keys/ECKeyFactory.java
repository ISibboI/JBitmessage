/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.ec.keys;

import codec.asn1.ASN1OctetString;
import codec.asn1.ASN1Sequence;
import codec.pkcs8.PrivateKeyInfo;
import codec.x509.SubjectPublicKeyInfo;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.exceptions.InvalidKeySpecException;
import de.flexiprovider.api.keys.Key;
import de.flexiprovider.api.keys.KeyFactory;
import de.flexiprovider.api.keys.KeySpec;
import de.flexiprovider.api.keys.PrivateKey;
import de.flexiprovider.api.keys.PublicKey;
import de.flexiprovider.api.parameters.AlgorithmParameters;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.math.ellipticcurves.EllipticCurve;
import de.flexiprovider.common.math.ellipticcurves.EllipticCurveGF2n;
import de.flexiprovider.common.math.ellipticcurves.EllipticCurveGFP;
import de.flexiprovider.common.math.ellipticcurves.Point;
import de.flexiprovider.common.math.ellipticcurves.PointGF2n;
import de.flexiprovider.common.math.ellipticcurves.PointGFP;
import de.flexiprovider.common.util.ASN1Tools;
import de.flexiprovider.ec.parameters.CurveParams;
import de.flexiprovider.pki.AlgorithmIdentifier;
import de.flexiprovider.pki.PKCS8EncodedKeySpec;
import de.flexiprovider.pki.PKITools;
import de.flexiprovider.pki.X509EncodedKeySpec;

/**
 * Key factories are used to convert keys (opaque cryptographic keys of type
 * Key) into key specifications (transparent representations of the underlying
 * key material), and vice versa. <BR>
 * <p>
 * Key factories are bi-directional. That is, they allow you to build an opaque
 * key object from a given key specification (key material), or to retrieve the
 * underlying key material of a key object in a suitable format.<BR>
 * <p>
 * This class provides the translation between a key specification (<tt>ECPrivateKeySpec</tt>
 * or <tt>ECPublicKeySpec</tt> or an ASN.1 / DER- representation, in this case
 * a PKCS8EncodedKeySpec or a X509EncodedKeySpec) and an <tt>ECPrivateKey</tt>
 * or an <tt>ECPublicKey</tt>-object.
 * 
 * @see "java.security.Key"
 * @see "java.security.KeyFactory"
 * @see "java.security.spec.KeySpec"
 * @see "java.security.spec.X509EncodedKeySpec"
 * @see de.flexiprovider.ec.keys.ECPrivateKeySpec
 * @see de.flexiprovider.common.math.ellipticcurves.Point
 * @see CurveParams
 * @author Birgit Henhapl
 * @author Michele Boivin
 */
public class ECKeyFactory extends KeyFactory {

    /**
     * The OID for ECDSA public keys (also used for ECDSA private keys).
     * 
     * <pre>
     *   id-publicKeyType   OBJECT IDENTIFIER ::= { ansi-X9-62 keyType(2) }
     *   id-ecPublicKeyType OBJECT IDENTIFIER ::= { id-publicKeyType 1 }
     * </pre>
     */
    public static final String OID = "1.2.840.10045.2.1";

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

	if (keySpec instanceof ECPrivateKeySpec) {
	    return new ECPrivateKey((ECPrivateKeySpec) keySpec);
	} else if (keySpec instanceof PKCS8EncodedKeySpec) {
	    // get the DER-encoded Key according to PKCS#8 from the spec
	    byte[] encKey = ((PKCS8EncodedKeySpec) keySpec).getEncoded();

	    // decode the PKCS#8 data structure to the pki object
	    PrivateKeyInfo pki = new PrivateKeyInfo();

	    try {
		ASN1Tools.derDecode(encKey, pki);

		// Get the private key as an instance of an ECPrivateKey
		// Sequence.
		ASN1Sequence privKeySequence = (ASN1Sequence) pki
			.getDecodedRawKey();

		// The ECPrivateKey sequence contains a version number, the
		// actual private key as an octet string, and optional
		// parameters. The parameters are always given in the PKCS #8
		// PrivateKeyInfo Sequence, so that there is no need to take the
		// parameters from the ECPrivateKey.
		ASN1OctetString oct = (ASN1OctetString) privKeySequence.get(1);
		FlexiBigInt priv = new FlexiBigInt(1, oct.getByteArray());

		// Get the parameters from the PrivateKeyInfo. The parameters
		// are in the AlgorithmIdentifier. The AlgorithmIdentifier must
		// be a Sequence.
		AlgorithmIdentifier algId = PKITools
			.getAlgorithmIdentifier(pki);
		AlgorithmParameters params = algId.getParams();
		CurveParams paramSpec = (CurveParams) params
			.getParameterSpec(CurveParams.class);

		return new ECPrivateKey(priv, paramSpec);

	    } catch (Exception e) {
		throw new InvalidKeySpecException(e.getClass().getName() + ": "
			+ e.getMessage());
	    }
	}

	throw new InvalidKeySpecException("Unsupported key specification: "
		+ keySpec + ".");
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

	if (keySpec instanceof ECPublicKeySpec) {
	    ECPublicKeySpec ecPubSpec = (ECPublicKeySpec) keySpec;

	    // either create a public key with parameters
	    if (ecPubSpec.getParams() != null) {
		return new ECPublicKey(ecPubSpec.getW(), ecPubSpec.getParams());
	    }

	    // ... or one without (having the public point as uncompressed
	    // encoding)
	    return new ECPublicKey(ecPubSpec.getEncodedW());

	} else if (keySpec instanceof X509EncodedKeySpec) {
	    // get the DER-encoded Key according to X.509 from the spec
	    byte[] encKey = ((X509EncodedKeySpec) keySpec).getEncoded();

	    // decode the X.509 data structure to the spki object
	    SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo();
	    try {
		ASN1Tools.derDecode(encKey, spki);

		// get the public key as a byte array.
		byte[] pubKeyBytes = spki.getRawKey();

		// Get the parameters from the SubjectPublicKeyInfo.
		// The parameters are in the AlgorithmIdentifier.
		// The AlgorithmIdentifier must be a Sequence.
		AlgorithmIdentifier algId = PKITools
			.getAlgorithmIdentifier(spki);
		AlgorithmParameters aparam = algId.getParams();

		// see if EC domain parameters are specified for this public key
		if (aparam == null) {
		    return new ECPublicKey(pubKeyBytes);
		}

		// initialize the AlgorithmParameters.
		CurveParams ecParamSpec = (CurveParams) aparam
			.getParameterSpec(CurveParams.class);

		EllipticCurve mE = ecParamSpec.getE();

		// make a point out of the byte array
		Point mW = null;
		if (mE instanceof EllipticCurveGFP) {
		    mW = new PointGFP(pubKeyBytes, (EllipticCurveGFP) mE);
		} else if (mE instanceof EllipticCurveGF2n) {
		    mW = new PointGF2n(pubKeyBytes, (EllipticCurveGF2n) mE);
		} else {
		    throw new InvalidKeySpecException(
			    "EllipticCurve must be an instance either of "
				    + "EllipticCurveGFP or EllipticCurveGF2n.");
		}

		return new ECPublicKey(mW, ecParamSpec);

	    } catch (Exception e) {
		throw new InvalidKeySpecException(e.getClass().getName() + ": "
			+ e.getMessage());
	    }
	}

	throw new InvalidKeySpecException("Unsupported key specification: "
		+ keySpec + ".");
    }

    /**
     * Returns a specification (key material) of the given key object.
     * <tt>keySpec</tt> identifies the specification class in which the key
     * material should be returned. It could, for example, be
     * <tt>ECPublicKeySpec.class</tt>, to indicate that the key material
     * should be returned in an instance of the <tt>ECPublicKeySpec</tt>
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

	if (key instanceof ECPublicKey) {
	    if (X509EncodedKeySpec.class.isAssignableFrom(keySpec)) {
		return new X509EncodedKeySpec(key.getEncoded());
	    } else if (ECPublicKeySpec.class.isAssignableFrom(keySpec)) {
		ECPublicKey pubKey = (ECPublicKey) key;
		Point w = null;
		try {
		    w = pubKey.getW();
		} catch (InvalidKeyException e) {
		    throw new InvalidKeySpecException(
			    "No EC domain parameters defined for this key. KeySpec cannot be generated.");
		}
		return new ECPublicKeySpec(w, pubKey.getParams());
	    }
	} else if (key instanceof ECPrivateKey) {
	    if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec)) {
		return new PKCS8EncodedKeySpec(key.getEncoded());
	    } else if (ECPrivateKeySpec.class.isAssignableFrom(keySpec)) {
		ECPrivateKey privKey = (ECPrivateKey) key;
		return new ECPrivateKeySpec(privKey.getS(), privKey.getParams());
	    }
	} else {
	    throw new InvalidKeySpecException("Unsupported key type: "
		    + key.getClass() + ".");
	}

	throw new InvalidKeySpecException("Unsupported key specification: "
		+ keySpec + ".");
    }

    /**
     * Translates a key object, whose provider may be unknown or potentially
     * untrusted, into a corresponding key object of this key factory.
     * 
     * @param key
     *                the key whose provider is unknown or untrusted
     * @return the translated key
     * @throws InvalidKeyException
     *                 if the given key cannot be processed by this key factory.
     */
    public Key translateKey(Key key) throws InvalidKeyException {

	try {
	    if (key instanceof ECPublicKey) {
		// Check if key originates from this factory
		if (key instanceof ECPublicKey) {
		    return key;
		}
		// Convert key to spec
		ECPublicKeySpec ecPubKeySpec = (ECPublicKeySpec) getKeySpec(
			key, ECPublicKeySpec.class);
		// Create key from spec, and return it
		return generatePublic(ecPubKeySpec);
	    } else if (key instanceof ECPrivateKey) {
		// Check if key originates from this factory
		if (key instanceof ECPrivateKey) {
		    return key;
		}
		// Convert key to spec
		ECPrivateKeySpec ecPrivKeySpec = (ECPrivateKeySpec) getKeySpec(
			key, ECPrivateKeySpec.class);
		// Create key from spec, and return it
		return generatePrivate(ecPrivKeySpec);
	    } else {
		throw new InvalidKeyException("Wrong algorithm type");
	    }
	} catch (InvalidKeySpecException e) {
	    throw new InvalidKeyException("Cannot translate key: "
		    + e.getMessage());
	}
    }

}
