/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.dsa;

import codec.CorruptedCodeException;
import codec.asn1.ASN1Integer;
import codec.asn1.ASN1Type;
import codec.pkcs8.PrivateKeyInfo;
import codec.x509.SubjectPublicKeyInfo;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.exceptions.InvalidKeySpecException;
import de.flexiprovider.api.exceptions.InvalidParameterSpecException;
import de.flexiprovider.api.exceptions.NoSuchAlgorithmException;
import de.flexiprovider.api.keys.Key;
import de.flexiprovider.api.keys.KeySpec;
import de.flexiprovider.api.keys.PrivateKey;
import de.flexiprovider.api.keys.PublicKey;
import de.flexiprovider.api.parameters.AlgorithmParameters;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.util.ASN1Tools;
import de.flexiprovider.core.dsa.interfaces.DSAParams;
import de.flexiprovider.pki.AlgorithmIdentifier;
import de.flexiprovider.pki.PKCS8EncodedKeySpec;
import de.flexiprovider.pki.PKITools;
import de.flexiprovider.pki.X509EncodedKeySpec;

/**
 * This class is able to transform DSA-keys and DSA-key specs into a form that
 * can be used with the FlexiCoreProvider.
 * 
 * @author Thomas Wahrenbruch
 * @author Michele Boivin
 */
public class DSAKeyFactory extends
		de.flexiprovider.core.dsa.interfaces.DSAKeyFactory {

	/**
	 * The OID of DSA.
	 */
	public static final String OID = "1.2.840.10040.4.1";

	/**
	 * An alternative OID of DSA.
	 */
	public static final String OID2 = "1.3.14.3.2.12";

	/**
	 * Converts, if possible, a key specification into a DSAPrivKey. Currently
	 * the following key specifications are supported: DSAPrivateKeySpec,
	 * PKCS8EncodedKeySpec.
	 * 
	 * @param keySpec
	 *            the key specification.
	 * @return the private DSA key.
	 * @throws InvalidKeySpecException
	 *             if the key specification is not supported.
	 * @see de.flexiprovider.core.dsa.DSAPrivateKey
	 */
	public PrivateKey generatePrivate(KeySpec keySpec)
			throws InvalidKeySpecException {

		if (keySpec instanceof DSAPrivateKeySpec) {
			return new DSAPrivateKey((DSAPrivateKeySpec) keySpec);
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

			// get the inner type inside the OCTET STRING
			ASN1Integer key = null;
			try {
				key = (ASN1Integer) pki.getDecodedRawKey();
			} catch (CorruptedCodeException CCExc) {
				throw new InvalidKeySpecException(CCExc.getMessage());
			}
			FlexiBigInt y = ASN1Tools.getFlexiBigInt(key);

			// Get the parameters from the PrivateKeyInfo.
			// The parameters are in the AlgorithmIdentifier.
			AlgorithmIdentifier algId = PKITools.getAlgorithmIdentifier(pki);
			AlgorithmParameters aparam = null;
			try {
				aparam = algId.getParams();
			} catch (NoSuchAlgorithmException e) {
				throw new InvalidKeySpecException(e.getMessage());
			} catch (InvalidAlgorithmParameterException e) {
				throw new InvalidKeySpecException(e.getMessage());
			}

			DSAParameterSpec dsaps = null;
			try {
				dsaps = (DSAParameterSpec) aparam
						.getParameterSpec(DSAParameterSpec.class);
			} catch (InvalidParameterSpecException IPSExc) {
				throw new InvalidKeySpecException(
						"InvalidParameterSpecException: " + IPSExc.getMessage());
			}
			DSAParams params = dsaps;
			return new DSAPrivateKey(y, params);

		}

		throw new InvalidKeySpecException("Unsupported key specification: "
				+ keySpec + ".");
	}

	/**
	 * Converts, if possible, a key specification into a DSAPubKey. Currently
	 * the following key specifications are supported: DSAPublicKeySpec,
	 * X509EncodedKeySpec.
	 * 
	 * @param keySpec
	 *            the key specification.
	 * @return the public DSA key.
	 * @throws InvalidKeySpecException
	 *             if the KeySpec is not supported.
	 * @see de.flexiprovider.core.dsa.DSAPublicKey
	 */
	public PublicKey generatePublic(KeySpec keySpec)
			throws InvalidKeySpecException {
		if (keySpec instanceof DSAPublicKeySpec) {
			return new DSAPublicKey((DSAPublicKeySpec) keySpec);
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

			// get the inner type inside the BIT STRING
			ASN1Type key = null;

			try {
				key = spki.getDecodedRawKey(); // MM
			} catch (CorruptedCodeException CCExc) {
				throw new InvalidKeySpecException(CCExc.getMessage());
			}
			FlexiBigInt x = ASN1Tools.getFlexiBigInt((ASN1Integer) key);

			// Get the parameters from the SubjectPublicKeyInfo.
			// The parameters are in the AlgorithmIdentifier.
			// The AlgorithmIdentifier must be a Sequence.
			AlgorithmIdentifier algId = PKITools.getAlgorithmIdentifier(spki);

			AlgorithmParameters aparam = null;
			try {
				aparam = algId.getParams();
			} catch (NoSuchAlgorithmException e) {
				throw new InvalidKeySpecException(e.getMessage());
			} catch (InvalidAlgorithmParameterException e) {
				throw new InvalidKeySpecException(e.getMessage());
			}

			DSAParameterSpec dsaps = null;
			try {
				dsaps = (DSAParameterSpec) aparam
						.getParameterSpec(DSAParameterSpec.class);
			} catch (InvalidParameterSpecException IPSExc) {
				throw new InvalidKeySpecException(
						"InvalidParameterSpecException: " + IPSExc.getMessage());
			}
			DSAParams params = dsaps;
			return new DSAPublicKey(x, params);
		}

		throw new InvalidKeySpecException("Unsupported key specification: "
				+ keySpec + ".");
	}

	/**
	 * Converts a given key into a key specification, if possible. Currently the
	 * following specifications are supported:
	 * <ul>
	 * <li>for DSAPublicKey: X509EncodedKeySpec, DSAPublicKeySpec</li>
	 * <li>for DSAPrivateKey: PKCS8EncodedKeySpec, DSAPrivateKeySpec.</li>
	 * </ul>
	 * <p>
	 * 
	 * @param key
	 *            the key
	 * @param keySpec
	 *            the key specification
	 * @return the specification of the DSA key
	 * @throws InvalidKeySpecException
	 *             if the key type or key specification is not supported.
	 */
	public KeySpec getKeySpec(Key key, Class keySpec)
			throws InvalidKeySpecException {
		if (key instanceof DSAPublicKey) {
			if (X509EncodedKeySpec.class.isAssignableFrom(keySpec)) {
				return new X509EncodedKeySpec(key.getEncoded());
			} else if (DSAPublicKeySpec.class.isAssignableFrom(keySpec)) {
				DSAPublicKey dsaPubKey = (DSAPublicKey) key;
				DSAParams params = dsaPubKey.getParameters();
				return new DSAPublicKeySpec(dsaPubKey.getValueY(), params
						.getPrimeP(), params.getPrimeQ(), params.getBaseG());
			}
		} else if (key instanceof DSAPrivateKey) {
			if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec)) {
				return new PKCS8EncodedKeySpec(key.getEncoded());
			} else if (DSAPrivateKeySpec.class.isAssignableFrom(keySpec)) {
				DSAPrivateKey dsaPrivateKey = (DSAPrivateKey) key;
				DSAParams params = dsaPrivateKey.getParameters();
				return new DSAPrivateKeySpec(dsaPrivateKey.getValueX(), params
						.getPrimeP(), params.getPrimeQ(), params.getBaseG());
			}
		} else {
			throw new InvalidKeySpecException("Unsupported key type: "
					+ key.getClass() + ".");
		}

		throw new InvalidKeySpecException("Unsupported key specification: "
				+ keySpec + ".");
	}

	/**
	 * Translates a key into a form known by the CDC Standard Provider.
	 * Currently the following "source" keys are supported: DSAPrivateKey,
	 * DSAPublicKey.
	 * 
	 * @param key
	 *            the key
	 * @return a key of a known key-type
	 * @throws InvalidKeyException
	 *             if the key type is not supported.
	 */
	public Key translateKey(Key key) throws InvalidKeyException {
		if (key instanceof DSAPrivateKey) {
			if (key instanceof DSAPrivateKey) {
				return key;
			}
			DSAPrivateKey dsaKey = (DSAPrivateKey) key;
			return new DSAPrivateKey(dsaKey.getValueX(), dsaKey.getParameters());
		} else if (key instanceof DSAPublicKey) {
			if (key instanceof DSAPublicKey) {
				return key;
			}
			DSAPublicKey dsaKey = (DSAPublicKey) key;
			return new DSAPublicKey(dsaKey.getValueY(), dsaKey.getParameters());
		}

		throw new InvalidKeyException("Unsupported key type: " + key.getClass()
				+ ".");
	}

}
