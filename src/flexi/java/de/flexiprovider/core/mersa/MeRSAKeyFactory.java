/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.mersa;

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
import de.flexiprovider.core.rsa.RSAPublicKey;
import de.flexiprovider.core.rsa.RSAPublicKeySpec;
import de.flexiprovider.pki.PKCS8EncodedKeySpec;
import de.flexiprovider.pki.X509EncodedKeySpec;

/**
 * This class is able to transform MeRSA-keys and MeRSA-key specs into a form
 * that can be used with the FlexiProvider.
 * 
 * @author Erik Dahmen
 * @author Paul Nguentcheu
 */
public class MeRSAKeyFactory extends KeyFactory {

    /**
     * Converts, if possible, a key specification into a MeRSAPrivateKey.
     * Currently the following key specifications are supported:
     * MeRSAPrivateKeySpec, PKCS8EncodedKeySpec.
     * 
     * @see de.flexiprovider.core.mersa.MeRSAPrivateKey
     * @param keySpec
     *                the key specification
     * @return the private MeRSA key
     * @throws InvalidKeySpecException
     *                 if the KeySpec is not supported.
     */
    public PrivateKey generatePrivate(KeySpec keySpec)
	    throws InvalidKeySpecException {

	if (keySpec instanceof MeRSAPrivateKeySpec) {
	    return new MeRSAPrivateKey((MeRSAPrivateKeySpec) keySpec);
	} else if (keySpec instanceof PKCS8EncodedKeySpec) {

	    // get the DER-encoded Key according to PKCS#8 from the spec
	    byte[] encKey = ((PKCS8EncodedKeySpec) keySpec).getEncoded();

	    // decode the PKCS#8 data structure to the pki object
	    PrivateKeyInfo pki = new PrivateKeyInfo();
	    try {
		ASN1Tools.derDecode(encKey, pki);
	    } catch (Exception ce) {
		throw new InvalidKeySpecException(
			"Unable to decode PKCS8EncodedKeySpec.");
	    }

	    try {
		// build and return the actual key
		ASN1Sequence encPrivKey = (ASN1Sequence) pki.getDecodedRawKey();

		// the encoded MeRSA private key sequence contains 9
		// elements

		if (encPrivKey.size() == 11) {
		    // component(0) = Versionsnummer
		    // decode modulus
		    FlexiBigInt modulus = ASN1Tools
			    .getFlexiBigInt((ASN1Integer) encPrivKey.get(1));
		    // decode public exponent
		    FlexiBigInt publicExponent = ASN1Tools
			    .getFlexiBigInt((ASN1Integer) encPrivKey.get(2));
		    // decode exponent k
		    FlexiBigInt exponentK = ASN1Tools
			    .getFlexiBigInt((ASN1Integer) encPrivKey.get(3));
		    // decode private exponent
		    FlexiBigInt privateExponent = ASN1Tools
			    .getFlexiBigInt((ASN1Integer) encPrivKey.get(4));
		    // decode prime p
		    FlexiBigInt primeP = ASN1Tools
			    .getFlexiBigInt((ASN1Integer) encPrivKey.get(5));
		    // decode prime q
		    FlexiBigInt primeQ = ASN1Tools
			    .getFlexiBigInt((ASN1Integer) encPrivKey.get(6));
		    // decode exponent d mod p
		    FlexiBigInt exponentP = ASN1Tools
			    .getFlexiBigInt((ASN1Integer) encPrivKey.get(7));
		    // decode exponent d mod q
		    FlexiBigInt exponentQ = ASN1Tools
			    .getFlexiBigInt((ASN1Integer) encPrivKey.get(8));
		    // decode eInvP
		    FlexiBigInt e_inv_p = ASN1Tools
			    .getFlexiBigInt((ASN1Integer) encPrivKey.get(9));
		    // decode crt coefficient
		    FlexiBigInt crtCoefficient = ASN1Tools
			    .getFlexiBigInt((ASN1Integer) encPrivKey.get(10));

		    return new MeRSAPrivateKey(modulus, publicExponent,
			    privateExponent, primeP, primeQ, exponentP,
			    exponentQ, crtCoefficient, exponentK, e_inv_p);
		}
	    } catch (CorruptedCodeException cce) {
		throw new InvalidKeySpecException(
			"Unable to decode PKCS8EncodedKeySpec.");
	    }
	}

	throw new InvalidKeySpecException(
		"MeRSAKeyFactory: Unknown KeySpec type.");
    }

    /**
     * Converts, if possible, a key specification into a RSAPubKey. Currently
     * the following key specifications are supported: RSAPublicKeySpec,
     * X509EncodedKeySpec.
     * 
     * @param keySpec
     *                the key specification
     * @return the public RSA key
     * @throws InvalidKeySpecException
     *                 if the KeySpec is not supported.
     * @see de.flexiprovider.core.rsa.RSAPublicKey
     */
    public PublicKey generatePublic(KeySpec keySpec)
	    throws InvalidKeySpecException {

	if (keySpec instanceof RSAPublicKeySpec) {
	    return new RSAPublicKey((RSAPublicKeySpec) keySpec);
	} else if (keySpec instanceof X509EncodedKeySpec) {

	    // get the DER-encoded Key according to X.509 from the spec
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

		// the encoded RSA public key sequence must contain 2 elements
		if (encPubKey.size() == 2) {
		    // decode modulus
		    FlexiBigInt modulus = ASN1Tools
			    .getFlexiBigInt((ASN1Integer) encPubKey.get(0));
		    // decode public exponent
		    FlexiBigInt publicExponent = ASN1Tools
			    .getFlexiBigInt((ASN1Integer) encPubKey.get(1));

		    return new RSAPublicKey(modulus, publicExponent);
		}
	    } catch (CorruptedCodeException cce) {
		throw new InvalidKeySpecException(
			"Unable to decode X509EncodedKeySpec.");
	    }
	}

	throw new InvalidKeySpecException(
		"RSAKeyFactory: Unknown KeySpec type.");
    }

    /**
     * Converts a given key into a key specification, if possible. Currently the
     * following specifications are supported:
     * <ul>
     * <li>for RSAPublicKey: X509EncodedKeySpec, RSAPublicKeySpec</li>
     * <li>for MeRSAPrivateKey: PKCS8EncodedKeySpec, MeRSAPrivateKeySpec</li>
     * </ul>
     * 
     * @param key
     *                the key
     * @param keySpec
     *                the key specification
     * @return key specification of the MeRSA key
     * @throws InvalidKeySpecException
     *                 if the specification is not supported.
     */
    public KeySpec getKeySpec(Key key, Class keySpec)
	    throws InvalidKeySpecException {

	if (key instanceof RSAPublicKey) {
	    if (X509EncodedKeySpec.class.isAssignableFrom(keySpec)) {
		return new X509EncodedKeySpec(key.getEncoded());
	    } else if (RSAPublicKeySpec.class.isAssignableFrom(keySpec)) {
		RSAPublicKey rsaPublicKey = (RSAPublicKey) key;
		return new RSAPublicKeySpec(rsaPublicKey.getN(), rsaPublicKey
			.getE());
	    }
	} else if (key instanceof MeRSAPrivateKey) {
	    if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec)) {
		return new PKCS8EncodedKeySpec(key.getEncoded());
	    }

	    MeRSAPrivateKey rsaPrivCrtKey = (MeRSAPrivateKey) key;

	    if (MeRSAPrivateKeySpec.class.isAssignableFrom(keySpec)) {
		return new MeRSAPrivateKeySpec(rsaPrivCrtKey.getN(),
			rsaPrivCrtKey.getE(), rsaPrivCrtKey.getD(),
			rsaPrivCrtKey.getP(), rsaPrivCrtKey.getQ(),
			rsaPrivCrtKey.getDp(), rsaPrivCrtKey.getDq(),
			rsaPrivCrtKey.getCRTCoeff(), rsaPrivCrtKey.getK(),
			rsaPrivCrtKey.getEInvP());
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
     * following "source" keys are supported: MeRSAPrivateKey, RSAPublicKey.
     * 
     * @param key
     *                the key
     * @return a key of a known key type
     * @throws InvalidKeyException
     *                 if the key is not supported.
     */
    public Key translateKey(Key key) throws InvalidKeyException {
	if (key instanceof MeRSAPrivateKey) {
	    if (key instanceof MeRSAPrivateKey) {
		return key;
	    }

	    MeRSAPrivateKey rsaKey = (MeRSAPrivateKey) key;

	    return new MeRSAPrivateKey(rsaKey.getN(), rsaKey.getE(), rsaKey
		    .getD(), rsaKey.getP(), rsaKey.getQ(), rsaKey.getDp(),
		    rsaKey.getDq(), rsaKey.getCRTCoeff(), rsaKey.getK(), rsaKey
			    .getEInvP());
	} else if (key instanceof RSAPublicKey) {
	    if (key instanceof RSAPublicKey) {
		return key;
	    }

	    RSAPublicKey rsaKey = (RSAPublicKey) key;

	    return new RSAPublicKey(rsaKey.getN(), rsaKey.getE());
	}

	throw new InvalidKeyException("Unsupported key type.");
    }

}
