/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.rsa;

import codec.CorruptedCodeException;
import codec.asn1.ASN1Integer;
import codec.asn1.ASN1Sequence;
import codec.pkcs8.PrivateKeyInfo;
import codec.x509.SubjectPublicKeyInfo;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.exceptions.InvalidKeySpecException;
import de.flexiprovider.api.keys.Key;
import de.flexiprovider.api.keys.KeySpec;
import de.flexiprovider.api.keys.PrivateKey;
import de.flexiprovider.api.keys.PublicKey;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.util.ASN1Tools;
import de.flexiprovider.core.mprsa.MpRSAPrivateKey;
import de.flexiprovider.core.mprsa.MpRSAPrivateKeySpec;
import de.flexiprovider.core.mprsa.RSAOtherPrimeInfo;
import de.flexiprovider.pki.PKCS8EncodedKeySpec;
import de.flexiprovider.pki.X509EncodedKeySpec;

/**
 * This class is able to transform RSA-keys and RSA-key specs into a form that
 * can be used with the FlexiProvider.
 * 
 * @author Thomas Wahrenbruch
 */
public class RSAKeyFactory extends
		de.flexiprovider.core.rsa.interfaces.RSAKeyFactory {

	/**
	 * The OID of RSA.
	 */
	public static final String OID = "1.2.840.113549.1.1.1";

	/**
	 * Converts, if possible, a key specification into a RSAPubKey. Currently
	 * the following key specifications are supported: RSAPublicKeySpec,
	 * X509EncodedKeySpec.
	 * 
	 * @param keySpec
	 *            the key specification
	 * @return the public RSA key
	 * @throws InvalidKeySpecException
	 *             if the KeySpec is not supported.
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
	 * Converts, if possible, a key specification into an {@link RSAPrivateKey},
	 * an {@link RSAPrivateCrtKey}, or an {@link MpRSAPrivateKey}. Currently the
	 * following key specifications are supported: RSAPrivateCrtKeySpec,
	 * RSAPrivateKeySpec, PKCS8EncodedKeySpec.
	 * 
	 * @see de.flexiprovider.core.rsa.RSAPrivateCrtKey
	 * @see de.flexiprovider.core.rsa.RSAPrivateKey
	 * @param keySpec
	 *            the key specification
	 * @return the private RSA key
	 * @throws InvalidKeySpecException
	 *             if the KeySpec is not supported.
	 */
	public PrivateKey generatePrivate(KeySpec keySpec)
			throws InvalidKeySpecException {

		if (keySpec instanceof RSAPrivateKeySpec) {
			return new RSAPrivateKey((RSAPrivateKeySpec) keySpec);
		} else if (keySpec instanceof RSAPrivateCrtKeySpec) {
			return new RSAPrivateCrtKey((RSAPrivateCrtKeySpec) keySpec);
		} else if (keySpec instanceof MpRSAPrivateKeySpec) {
			return new MpRSAPrivateKey((MpRSAPrivateKeySpec) keySpec);
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

				// the encoded RSA private key sequence contains 2, 3, 9, or 10
				// elements (2 elements because version is optional)
				if (encPrivKey.size() == 2) {
					// decode modulus
					FlexiBigInt modulus = ASN1Tools
							.getFlexiBigInt((ASN1Integer) encPrivKey.get(0));
					// decode private exponent
					FlexiBigInt privateExponent = ASN1Tools
							.getFlexiBigInt((ASN1Integer) encPrivKey.get(1));

					return new RSAPrivateKey(modulus, privateExponent);
				} else if (encPrivKey.size() == 3) {
					// component(0) = Versionsnummer
					// decode modulus
					FlexiBigInt modulus = ASN1Tools
							.getFlexiBigInt((ASN1Integer) encPrivKey.get(1));
					// decode private exponent
					FlexiBigInt privateExponent = ASN1Tools
							.getFlexiBigInt((ASN1Integer) encPrivKey.get(2));

					return new RSAPrivateKey(modulus, privateExponent);
				} else if (encPrivKey.size() == 9) {
					// component(0) = Versionsnummer
					// decode modulus
					FlexiBigInt modulus = ASN1Tools
							.getFlexiBigInt((ASN1Integer) encPrivKey.get(1));
					// decode public exponent
					FlexiBigInt publicExponent = ASN1Tools
							.getFlexiBigInt((ASN1Integer) encPrivKey.get(2));
					// decode private exponent
					FlexiBigInt privateExponent = ASN1Tools
							.getFlexiBigInt((ASN1Integer) encPrivKey.get(3));
					// decode prime p
					FlexiBigInt primeP = ASN1Tools
							.getFlexiBigInt((ASN1Integer) encPrivKey.get(4));
					// decode prime q
					FlexiBigInt primeQ = ASN1Tools
							.getFlexiBigInt((ASN1Integer) encPrivKey.get(5));
					// decode exponent d mod p
					FlexiBigInt exponentP = ASN1Tools
							.getFlexiBigInt((ASN1Integer) encPrivKey.get(6));
					// decode exponent d mod q
					FlexiBigInt exponentQ = ASN1Tools
							.getFlexiBigInt((ASN1Integer) encPrivKey.get(7));
					// decode crt coefficient
					FlexiBigInt crtCoefficient = ASN1Tools
							.getFlexiBigInt((ASN1Integer) encPrivKey.get(8));

					return new RSAPrivateCrtKey(modulus, publicExponent,
							privateExponent, primeP, primeQ, exponentP,
							exponentQ, crtCoefficient);
				} else if (encPrivKey.size() == 10) {
					// component(0) = Versionsnummer
					// decode modulus
					FlexiBigInt modulus = ASN1Tools
							.getFlexiBigInt((ASN1Integer) encPrivKey.get(1));
					// decode public exponent
					FlexiBigInt publicExponent = ASN1Tools
							.getFlexiBigInt((ASN1Integer) encPrivKey.get(2));
					// decode private exponent
					FlexiBigInt privateExponent = ASN1Tools
							.getFlexiBigInt((ASN1Integer) encPrivKey.get(3));
					// decode prime p
					FlexiBigInt primeP = ASN1Tools
							.getFlexiBigInt((ASN1Integer) encPrivKey.get(4));
					// decode prime q
					FlexiBigInt primeQ = ASN1Tools
							.getFlexiBigInt((ASN1Integer) encPrivKey.get(5));
					// decode exponent d mod p
					FlexiBigInt exponentP = ASN1Tools
							.getFlexiBigInt((ASN1Integer) encPrivKey.get(6));
					// decode exponent d mod q
					FlexiBigInt exponentQ = ASN1Tools
							.getFlexiBigInt((ASN1Integer) encPrivKey.get(7));
					// decode crt coefficient
					FlexiBigInt crtCoefficient = ASN1Tools
							.getFlexiBigInt((ASN1Integer) encPrivKey.get(8));

					ASN1Sequence seq_of = (ASN1Sequence) encPrivKey.get(9);
					int k = seq_of.size();
					RSAOtherPrimeInfo[] otherPrimeInfo = new RSAOtherPrimeInfo[k];

					for (int i = 0; i < k; i++) {
						ASN1Sequence seq_i = (ASN1Sequence) seq_of.get(i);

						FlexiBigInt prime_ = ASN1Tools
								.getFlexiBigInt((ASN1Integer) seq_i.get(0));
						FlexiBigInt exponent_ = ASN1Tools
								.getFlexiBigInt((ASN1Integer) seq_i.get(1));
						FlexiBigInt crtCoefficient_ = ASN1Tools
								.getFlexiBigInt((ASN1Integer) seq_i.get(2));

						otherPrimeInfo[i] = new RSAOtherPrimeInfo(prime_,
								exponent_, crtCoefficient_);
					}

					return new MpRSAPrivateKey(modulus, publicExponent,
							privateExponent, primeP, primeQ, exponentP,
							exponentQ, crtCoefficient, otherPrimeInfo);
				}
			} catch (CorruptedCodeException cce) {
				throw new InvalidKeySpecException(
						"Unable to decode PKCS8EncodedKeySpec.");
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
	 * <li>for RSAPrivateKey: PKCS8EncodedKeySpec, RSAPrivateKeySpec</li>
	 * <li>for RSAPrivateCrtKey: PKCS8EncodedKeySpec, RSAPrivateKeySpec,
	 * RSAPrivateCrtKeySpec</li>
	 * <li>for MpRSAPrivateKey: PKCS8EncodedKeySpec, MpRSAPrivateKeySpec</li>
	 * </ul>
	 * 
	 * @param key
	 *            the key
	 * @param keySpec
	 *            the key specification
	 * @return key specification of the RSA key
	 * @throws InvalidKeySpecException
	 *             if the specification is not supported.
	 */
	public KeySpec getKeySpec(Key key, Class keySpec)
			throws InvalidKeySpecException {

		if (key instanceof RSAPublicKey) {
			if (X509EncodedKeySpec.class.isAssignableFrom(keySpec)) {
				return new X509EncodedKeySpec(key.getEncoded());
			} else if (RSAPublicKeySpec.class.isAssignableFrom(keySpec)) {
				RSAPublicKey rsaPublicKey = (RSAPublicKey) key;
				return new RSAPublicKeySpec(rsaPublicKey.getN(),
						rsaPublicKey.getE());
			}
		} else if (key instanceof RSAPrivateKey) {
			if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec)) {
				return new PKCS8EncodedKeySpec(key.getEncoded());
			} else if (RSAPrivateKeySpec.class.isAssignableFrom(keySpec)) {
				RSAPrivateKey rsaPrivKey = (RSAPrivateKey) key;

				return new RSAPrivateKeySpec(rsaPrivKey.getN(),
						rsaPrivKey.getD());
			}
		} else if (key instanceof RSAPrivateCrtKey) {
			if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec)) {
				return new PKCS8EncodedKeySpec(key.getEncoded());
			}

			RSAPrivateCrtKey rsaPrivCrtKey = (RSAPrivateCrtKey) key;
			// RSAPrivateCrtKeySpec is a subclass of RSAPrivateKeySpec, thus
			// it must be tested first.
			if (RSAPrivateCrtKeySpec.class.isAssignableFrom(keySpec)) {
				return new RSAPrivateCrtKeySpec(rsaPrivCrtKey.getN(),
						rsaPrivCrtKey.getE(), rsaPrivCrtKey.getD(),
						rsaPrivCrtKey.getP(), rsaPrivCrtKey.getQ(),
						rsaPrivCrtKey.getDp(), rsaPrivCrtKey.getDq(),
						rsaPrivCrtKey.getCRTCoeff());
			} else if (RSAPrivateKeySpec.class.isAssignableFrom(keySpec)) {
				return new RSAPrivateKeySpec(rsaPrivCrtKey.getN(),
						rsaPrivCrtKey.getD());
			}
		} else if (key instanceof MpRSAPrivateKey) {
			if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec)) {
				return new PKCS8EncodedKeySpec(key.getEncoded());
			}

			MpRSAPrivateKey mpRSAPrivKey = (MpRSAPrivateKey) key;

			if (MpRSAPrivateKeySpec.class.isAssignableFrom(keySpec)) {
				return new MpRSAPrivateKeySpec(mpRSAPrivKey.getN(),
						mpRSAPrivKey.getE(), mpRSAPrivKey.getD(),
						mpRSAPrivKey.getP(), mpRSAPrivKey.getQ(),
						mpRSAPrivKey.getDp(), mpRSAPrivKey.getDq(),
						mpRSAPrivKey.getCRTCoeff(),
						mpRSAPrivKey.getOtherPrimeInfo());
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
	 * following "source" keys are supported: {@link RSAPrivateCrtKey},
	 * {@link RSAPrivateKey}, [@link MpRSAPrivateKey}, {@link RSAPublicKey}.
	 * 
	 * @param key
	 *            the key
	 * @return a key of a known key type
	 * @throws InvalidKeyException
	 *             if the key is not supported.
	 */
	public Key translateKey(Key key) throws InvalidKeyException {
		if ((key instanceof RSAPrivateCrtKey) || (key instanceof RSAPrivateKey)
				|| (key instanceof MpRSAPrivateKey)
				|| (key instanceof RSAPublicKey)) {
			return key;
		}
		throw new InvalidKeyException("Unsupported key type.");
	}

}
