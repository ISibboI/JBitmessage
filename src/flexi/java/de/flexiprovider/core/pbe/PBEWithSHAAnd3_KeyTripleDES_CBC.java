/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.pbe;

import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.exceptions.InvalidKeySpecException;
import de.flexiprovider.api.exceptions.NoSuchPaddingException;
import de.flexiprovider.api.keys.Key;
import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.api.keys.SecretKeyFactory;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.mode.ModeParameterSpec;
import de.flexiprovider.core.desede.DESede;
import de.flexiprovider.core.desede.DESedeKeyFactory;
import de.flexiprovider.core.desede.DESedeKeySpec;
import de.flexiprovider.core.kdf.PBKDF1_PKCS12;
import de.flexiprovider.core.kdf.PBKDF1_PKCS12ParameterSpec;

/**
 * This class implements passphrase based encryption (PBE) as defined in <a
 * href="http://www.rsasecurity.com/rsalabs/pkcs/pkcs-12/index.html">PKCS#12
 * version 1.2</a>. The key for the cipher (here DES) is derived from the
 * passphrase by applying a hashfunction (here
 * {@link de.flexiprovider.core.md.SHA1 SHA-1}) several times on it. Because we
 * don't provide single DES, {@link de.flexiprovider.core.desede.DESede DESede}
 * with the same key for encryption, decryption, encryption is used instead.
 * 
 * @author Michele Boivin
 */
public class PBEWithSHAAnd3_KeyTripleDES_CBC extends PBES1 {

	/**
	 * The OID of PBEWithSHAAnd3_KeyTripleDES_CBC.
	 */
	public static final String OID = "1.2.840.113549.1.12.1.3";

	// SecretKeyFactory for the tranformation DESKeySpec -> DESKey
	private SecretKeyFactory desKeyFactory;

	/**
	 * The default constructor tries to initialize the message digest, the
	 * secret key factory and the cipher.
	 */
	public PBEWithSHAAnd3_KeyTripleDES_CBC() {
		// a little trick, 'cause we don't provide single DES
		// we take DES ede with the same key for each round.
		cipher = new DESede.DESede_CBC();
		try {
			cipher.setPadding("PKCS5Padding");
		} catch (NoSuchPaddingException nspe) {
			throw new RuntimeException("internal error");
		}
		desKeyFactory = new DESedeKeyFactory();
		kdf = new PBKDF1_PKCS12.SHA1();
	}

	/**
	 * @return the name of this cipher
	 */
	public String getName() {
		return "PbeWithSHAAnd3_KeyTripleDES_CBC";
	}

	/**
	 * Returns the key size of the given key object. Since the cipher underlying
	 * this PBE scheme is DES, we always return 112 as the effective key size if
	 * the key is valid.
	 * 
	 * @param key
	 *            the key object
	 * @return the key size of the given key object.
	 * @throws InvalidKeyException
	 *             if key is not an instance of <tt>PBEKey</tt>
	 */
	public int getKeySize(Key key) throws InvalidKeyException {
		if (key instanceof PBEKey) {
			return 112;
		}
		throw new InvalidKeyException("Unsupported key.");
	}

	/**
	 * Initializes this cipher with a key, a set of algorithm parameters, and a
	 * source of randomness.
	 * <p>
	 * The cipher is initialized for encryption.
	 * <p>
	 * If this cipher requires any algorithm parameters and params is null, the
	 * underlying cipher implementation is supposed to generate the required
	 * parameters itself (using provider-specific default or random values) if
	 * it is being initialized for encryption, and raise an
	 * InvalidAlgorithmParameterException if it is being initialized for
	 * decryption. The generated parameters can be retrieved using
	 * engineGetParameters or engineGetIV (if the parameter is an IV).
	 * <p>
	 * If this cipher (including its underlying feedback or padding scheme)
	 * requires any random bytes (e.g., for parameter generation), it will get
	 * them from random.
	 * <p>
	 * Note that when a Cipher object is initialized, it loses all
	 * previously-acquired state. In other words, initializing a Cipher is
	 * equivalent to creating a new instance of that Cipher and initializing it.
	 * 
	 * @param key
	 *            the encryption key
	 * @param params
	 *            the algorithm parameters
	 * @param random
	 *            the source of randomness
	 * @throws InvalidKeyException
	 *             if the given key is inappropriate for initializing this
	 *             cipher
	 * @throws InvalidAlgorithmParameterException
	 *             if the given algorithm parameters are inappropriate for this
	 *             cipher, or if this cipher is being initialized fro decryption
	 *             and requires algorithm parameters and params is null
	 */
	public void initEncrypt(Key key, AlgorithmParameterSpec params,
			SecureRandom random) throws InvalidKeyException,
			InvalidAlgorithmParameterException {

		// check key type
		if (!(key instanceof PBEKey)) {
			throw new InvalidKeyException("unsupported type");
		}
		byte[] pbeKey = key.getEncoded();

		// check parameters type
		if (!(params instanceof PBEParameterSpec)) {
			throw new InvalidAlgorithmParameterException("unsupported type");
		}
		PBEParameterSpec pbeParamSpec = (PBEParameterSpec) params;

		// extract the salt and the iteration count from the parameters
		byte[] salt = pbeParamSpec.getSalt();
		int iterationCount = pbeParamSpec.getIterationCount();

		// generate the key bytes for the DESede key
		PBKDF1_PKCS12ParameterSpec kdfParams = new PBKDF1_PKCS12ParameterSpec(
				salt, iterationCount, PBKDF1_PKCS12ParameterSpec.ID_ENCRYPTION);
		kdf.init(pbeKey, kdfParams);
		byte[] desBytes = kdf.deriveKey(DESedeKeySpec.DES_EDE_KEY_LEN);

		// generate a new DESede key spec
		DESedeKeySpec desKeySpec = new DESedeKeySpec(desBytes);

		// convert the DESedeKeySpec into a DESKey
		SecretKey desKey;
		try {
			desKey = desKeyFactory.generateSecret(desKeySpec);
		} catch (InvalidKeySpecException ikse) {
			// the key spec is correct and must be accepted
			throw new RuntimeException("internal error");
		}

		// generate the key bytes for the IV
		kdfParams = new PBKDF1_PKCS12ParameterSpec(salt, iterationCount,
				PBKDF1_PKCS12ParameterSpec.ID_IV);
		kdf.init(pbeKey, kdfParams);
		byte[] ivBytes = kdf.deriveKey(8);

		// generate the IV
		ModeParameterSpec modeParams = new ModeParameterSpec(ivBytes);

		// initialize the DESede cipher
		cipher.initEncrypt(desKey, modeParams, (AlgorithmParameterSpec) null,
				random);
	}

	/**
	 * Initializes this cipher with a key, a set of algorithm parameters, and a
	 * source of randomness.
	 * <p>
	 * The cipher is initialized for decryption.
	 * <p>
	 * If this cipher requires any algorithm parameters and params is null, the
	 * underlying cipher implementation is supposed to generate the required
	 * parameters itself (using provider-specific default or random values) if
	 * it is being initialized for encryption, and raise an
	 * InvalidAlgorithmParameterException if it is being initialized for
	 * decryption. The generated parameters can be retrieved using
	 * engineGetParameters or engineGetIV (if the parameter is an IV).
	 * <p>
	 * If this cipher (including its underlying feedback or padding scheme)
	 * requires any random bytes (e.g., for parameter generation), it will get
	 * them from random.
	 * <p>
	 * Note that when a Cipher object is initialized, it loses all
	 * previously-acquired state. In other words, initializing a Cipher is
	 * equivalent to creating a new instance of that Cipher and initializing it.
	 * 
	 * @param key
	 *            the encryption key
	 * @param params
	 *            the algorithm parameters
	 * @throws InvalidKeyException
	 *             if the given key is inappropriate for initializing this
	 *             cipher
	 * @throws InvalidAlgorithmParameterException
	 *             if the given algorithm parameters are inappropriate for this
	 *             cipher, or if this cipher is being initialized fro decryption
	 *             and requires algorithm parameters and params is null
	 */
	public void initDecrypt(Key key, AlgorithmParameterSpec params)
			throws InvalidKeyException, InvalidAlgorithmParameterException {

		// check key type
		if (!(key instanceof PBEKey)) {
			throw new InvalidKeyException("unsupported type");
		}
		byte[] pbeKey = key.getEncoded();

		// check parameters type
		if (!(params instanceof PBEParameterSpec)) {
			throw new InvalidAlgorithmParameterException("unsupported type");
		}
		PBEParameterSpec pbeParamSpec = (PBEParameterSpec) params;

		// extract the salt and the iteration count from the parameters
		byte[] salt = pbeParamSpec.getSalt();
		int iterationCount = pbeParamSpec.getIterationCount();

		// generate the key bytes for the DESede key
		PBKDF1_PKCS12ParameterSpec kdfParams = new PBKDF1_PKCS12ParameterSpec(
				salt, iterationCount, PBKDF1_PKCS12ParameterSpec.ID_ENCRYPTION);
		kdf.init(pbeKey, kdfParams);
		byte[] desBytes = kdf.deriveKey(24);

		// generate a new DESede key spec
		DESedeKeySpec desKeySpec = new DESedeKeySpec(desBytes);

		// convert the DESedeKeySpec into a DESKey
		SecretKey desKey;
		try {
			desKey = desKeyFactory.generateSecret(desKeySpec);
		} catch (InvalidKeySpecException ikse) {
			// the key spec is correct and must be accepted
			throw new RuntimeException("internal error");
		}

		// generate the key bytes for the IV
		kdfParams = new PBKDF1_PKCS12ParameterSpec(salt, iterationCount,
				PBKDF1_PKCS12ParameterSpec.ID_IV);
		kdf.init(pbeKey, kdfParams);
		byte[] ivBytes = kdf.deriveKey(8);

		// generate the IV
		ModeParameterSpec modeParams = new ModeParameterSpec(ivBytes);

		// initialize the DESede cipher
		cipher.initDecrypt(desKey, modeParams, (AlgorithmParameterSpec) null);
	}
}
