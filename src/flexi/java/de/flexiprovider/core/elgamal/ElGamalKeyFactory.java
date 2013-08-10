/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.elgamal;

import codec.CorruptedCodeException;
import codec.asn1.ASN1Integer;
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
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.util.ASN1Tools;
import de.flexiprovider.pki.PKCS8EncodedKeySpec;
import de.flexiprovider.pki.X509EncodedKeySpec;

/**
 * This class is able to transform ElGamal-keys and ElGamal-key specs into a
 * form that can be used with the FlexiCoreProvider.
 * 
 * @see ElGamal
 * @author Thomas Wahrenbruch
 */
public class ElGamalKeyFactory extends KeyFactory {

    /**
     * The OID of ElGamal.
     */
    public static final String OID = "1.3.14.7.2.1.1";

    /**
     * Converts, if possible, a key specification into a ElGamalPrivateKey.
     * Currently the following key specifications are supported:
     * ElGamalPrivateKeySpec, PKCS8EncodedKeySpec.
     * 
     * @param keySpec
     *                the key specification
     * @return the private ElGamal key
     * @throws InvalidKeySpecException
     *                 if the KeySpec is not supported.
     * @see de.flexiprovider.core.elgamal.ElGamalPrivateKey
     * @see de.flexiprovider.core.elgamal.ElGamalPrivateKeySpec
     */
    public PrivateKey generatePrivate(KeySpec keySpec)
	    throws InvalidKeySpecException {

	if (keySpec instanceof ElGamalPrivateKeySpec) {
	    return new ElGamalPrivateKey((ElGamalPrivateKeySpec) keySpec);
	} else if (keySpec instanceof PKCS8EncodedKeySpec) {
	    // get the DER-encoded key according to X.509 from the spec
	    byte[] enc = ((PKCS8EncodedKeySpec) keySpec).getEncoded();

	    // decode the PrivateKeyInfo data structure to the pki object
	    PrivateKeyInfo pki = new PrivateKeyInfo();
	    try {
		ASN1Tools.derDecode(enc, pki);
	    } catch (Exception ce) {
		throw new InvalidKeySpecException(
			"Unable to decode PKCS8EncodedKeySpec.");
	    }

	    try {
		// build and return the actual key
		ASN1Sequence encPrivKey = (ASN1Sequence) pki.getDecodedRawKey();

		// decode modulus
		FlexiBigInt modulus = ASN1Tools
			.getFlexiBigInt((ASN1Integer) encPrivKey.get(0));
		// decode generator
		FlexiBigInt generator = ASN1Tools
			.getFlexiBigInt((ASN1Integer) encPrivKey.get(1));
		// decode publicA
		FlexiBigInt publicA = ASN1Tools
			.getFlexiBigInt((ASN1Integer) encPrivKey.get(2));
		// decode a
		FlexiBigInt a = ASN1Tools
			.getFlexiBigInt((ASN1Integer) encPrivKey.get(3));

		return new ElGamalPrivateKey(modulus, generator, publicA, a);

	    } catch (CorruptedCodeException cce) {
		throw new InvalidKeySpecException(
			"Unable to decode PKCS8EncodedKeySpec.");
	    }
	}

	throw new InvalidKeySpecException("Unknown key specification: "
		+ keySpec + ".");
    }

    /**
     * Converts, if possible, a key specification into a ElGamalPublicKey.
     * Currently the following key specifications are supported:
     * ElGamalPublicKeySpec, X509EncodedKeySpec.
     * 
     * @param keySpec
     *                the key specification
     * @return the public ElGamal key
     * @throws InvalidKeySpecException
     *                 if the KeySpec is not supported.
     * @see de.flexiprovider.core.elgamal.ElGamalPublicKey
     * @see de.flexiprovider.core.elgamal.ElGamalPublicKeySpec
     */
    public PublicKey generatePublic(KeySpec keySpec)
	    throws InvalidKeySpecException {

	if (keySpec instanceof ElGamalPublicKeySpec) {
	    return new ElGamalPublicKey((ElGamalPublicKeySpec) keySpec);
	} else if (keySpec instanceof X509EncodedKeySpec) {
	    // get the DER-encoded key according to X.509 from the spec
	    byte[] enc = ((X509EncodedKeySpec) keySpec).getEncoded();

	    // decode the SubjectPublicKeyInfo data structure to the pki object
	    SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo();
	    try {
		ASN1Tools.derDecode(enc, spki);
	    } catch (Exception ce) {
		throw new InvalidKeySpecException(
			"Unable to decode X509EncodedKeySpec.");
	    }

	    try {
		// build and return the actual key
		ASN1Sequence encPubKey = (ASN1Sequence) spki.getDecodedRawKey();

		// decode modulus
		FlexiBigInt modulus = ASN1Tools
			.getFlexiBigInt((ASN1Integer) encPubKey.get(0));
		// decode generator
		FlexiBigInt generator = ASN1Tools
			.getFlexiBigInt((ASN1Integer) encPubKey.get(1));
		// decode publicA
		FlexiBigInt publicA = ASN1Tools
			.getFlexiBigInt((ASN1Integer) encPubKey.get(2));

		return new ElGamalPublicKey(modulus, generator, publicA);

	    } catch (CorruptedCodeException cce) {
		throw new InvalidKeySpecException(
			"Unable to decode X509EncodedKeySpec.");
	    }
	}

	throw new InvalidKeySpecException("Unknown key specification: "
		+ keySpec + ".");
    }

    /**
     * Converts a given key into a key specification, if possible. Currently the
     * following key specifications are supported:
     * <ul>
     * <li>for ElGamalPublicKey: X509EncodedKeySpec, ElGamalPublicKeySpec</li>
     * <li>for ElGamalPrivateKey: PKCS8EncodedKeySpec, ElGamalPrivateKeySpec</li>
     * </ul>
     * 
     * @param key
     *                the key
     * @param keySpec
     *                the class of which type the returned class should be
     * @return the specification of the ElGamal key
     * @throws InvalidKeySpecException
     *                 if the specification is not supported.
     * @see de.flexiprovider.core.elgamal.ElGamalPrivateKey
     * @see de.flexiprovider.core.elgamal.ElGamalPublicKey
     * @see de.flexiprovider.core.elgamal.ElGamalPrivateKeySpec
     * @see de.flexiprovider.core.elgamal.ElGamalPublicKeySpec
     */
    public KeySpec getKeySpec(Key key, Class keySpec)
	    throws InvalidKeySpecException {

	if (key instanceof ElGamalPublicKey) {
	    if (X509EncodedKeySpec.class.isAssignableFrom(keySpec)) {
		return new X509EncodedKeySpec(key.getEncoded());
	    } else if (ElGamalPublicKeySpec.class.isAssignableFrom(keySpec)) {
		ElGamalPublicKey elGamalPubKey = (ElGamalPublicKey) key;
		return new ElGamalPublicKeySpec(elGamalPubKey.getModulus(),
			elGamalPubKey.getGenerator(), elGamalPubKey
				.getPublicA());
	    }
	} else if (key instanceof ElGamalPrivateKey) {
	    if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec)) {
		return new PKCS8EncodedKeySpec(key.getEncoded());
	    } else if (ElGamalPrivateKeySpec.class.isAssignableFrom(keySpec)) {
		ElGamalPrivateKey elGamalPrivKey = (ElGamalPrivateKey) key;
		return new ElGamalPrivateKeySpec(elGamalPrivKey.getModulus(),
			elGamalPrivKey.getGenerator(), elGamalPrivKey
				.getPublicA(), elGamalPrivKey.getA());
	    }
	} else {
	    throw new InvalidKeySpecException("Unsupported key type: "
		    + key.getClass() + ".");
	}

	throw new InvalidKeySpecException("Unknown key specification: "
		+ keySpec + ".");
    }

    /**
     * Translates a key into a form known by the FlexiProvider. Currently the
     * following "source" keys are supported: ElGamalPublicKey,
     * ElGamalPrivateKey.
     * 
     * @param key
     *                the key
     * @return a key of a known key-type
     * @throws InvalidKeyException
     *                 if the key is not supported.
     */
    public Key translateKey(Key key) throws InvalidKeyException {
	if (key instanceof ElGamalPublicKey || key instanceof ElGamalPrivateKey) {
	    return key;
	}
	throw new InvalidKeyException("Unsupported key type.");
    }

}
