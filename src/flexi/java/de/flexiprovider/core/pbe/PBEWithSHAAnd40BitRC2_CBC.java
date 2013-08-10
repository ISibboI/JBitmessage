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
import de.flexiprovider.api.keys.SecretKeySpec;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.mode.ModeParameterSpec;
import de.flexiprovider.core.kdf.PBKDF1_PKCS12;
import de.flexiprovider.core.kdf.PBKDF1_PKCS12ParameterSpec;
import de.flexiprovider.core.rc2.RC2;
import de.flexiprovider.core.rc2.RC2KeyFactory;

/**
 * This class implements passphrase based encryption (PBE) as defined in <a
 * href="http://www.rsasecurity.com/rsalabs/pkcs/pkcs-12/index.html">PKCS#12
 * version 1.2</a>. The key for the cipher (here RC2) is derived from the
 * passphrase by applying a hashfunction (here
 * {@link de.flexiprovider.core.md.SHA1 SHA-1}) several times on it.
 * 
 * @author Michele Boivin
 */
public class PBEWithSHAAnd40BitRC2_CBC extends PBES1 {

    /**
     * The OID of PBEWithSHAAnd40BitRC2_CBC.
     */
    public static final String OID = "1.2.840.113549.1.12.1.6";

    // SecretKeyFactory is for the tranformation SecretKeySpec -> RC2Key
    private SecretKeyFactory rc2KeyFactory;

    /**
     * The default constructor tries to initialize the message digest, the
     * secret key factory and the cipher.
     */
    public PBEWithSHAAnd40BitRC2_CBC() {
	cipher = new RC2.RC2_CBC();
	try {
	    cipher.setPadding("PKCS5Padding");
	} catch (NoSuchPaddingException nspe) {
	    throw new RuntimeException("internal error");
	}
	rc2KeyFactory = new RC2KeyFactory();
	kdf = new PBKDF1_PKCS12.SHA1();
    }

    /**
     * @return the name of this cipher
     */
    public String getName() {
	return "PbeWithSHAAnd40BitRC2_CBC";
    }

    /**
     * Returns the key size of the given key object. Since the cipher underlying
     * this PBE scheme is 40 bit RC2, the return value is fixed.
     * 
     * @param key
     *                the key object
     * @return the key size of the given key object.
     * @throws InvalidKeyException
     *                 if key is not an instance of <tt>PBEKey</tt>
     */
    public int getKeySize(Key key) throws InvalidKeyException {
	if (key instanceof PBEKey) {
	    return 40;
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
     *                the encryption key
     * @param params
     *                the algorithm parameters
     * @param random
     *                the source of randomness
     * @throws InvalidKeyException
     *                 if the given key is inappropriate for initializing this
     *                 cipher
     * @throws InvalidAlgorithmParameterException
     *                 if the given algorithm parameters are inappropriate for
     *                 this cipher, or if this cipher is being initialized fro
     *                 decryption and requires algorithm parameters and params
     *                 is null
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

	// extract the salt and iteration count from the parameters
	byte[] salt = pbeParamSpec.getSalt();
	int iterationCount = pbeParamSpec.getIterationCount();

	// generate the key bytes for the RC2 key
	PBKDF1_PKCS12ParameterSpec kdfParams = new PBKDF1_PKCS12ParameterSpec(
		salt, iterationCount, PBKDF1_PKCS12ParameterSpec.ID_ENCRYPTION);
	kdf.init(pbeKey, kdfParams);
	byte[] rc2Bytes = kdf.deriveKey(5);

	// generate a new RC2 key spec
	SecretKeySpec rc2KeySpec = new SecretKeySpec(rc2Bytes, "RC2");

	// convert the RC2 key spec into an RC2 key
	SecretKey rc2Key;
	try {
	    rc2Key = rc2KeyFactory.generateSecret(rc2KeySpec);
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
	ModeParameterSpec iv = new ModeParameterSpec(ivBytes);

	// initialize the RC2 cipher
	cipher.initEncrypt(rc2Key, iv, null, random);
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
     *                the encryption key
     * @param params
     *                the algorithm parameters
     * @throws InvalidKeyException
     *                 if the given key is inappropriate for initializing this
     *                 cipher
     * @throws InvalidAlgorithmParameterException
     *                 if the given algorithm parameters are inappropriate for
     *                 this cipher, or if this cipher is being initialized fro
     *                 decryption and requires algorithm parameters and params
     *                 is null
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

	// extract the salt and iteration count from the parameters
	byte[] salt = pbeParamSpec.getSalt();
	int iterationCount = pbeParamSpec.getIterationCount();

	// generate the key bytes for the RC2 key
	PBKDF1_PKCS12ParameterSpec kdfParams = new PBKDF1_PKCS12ParameterSpec(
		salt, iterationCount, PBKDF1_PKCS12ParameterSpec.ID_ENCRYPTION);
	kdf.init(pbeKey, kdfParams);
	byte[] rc2Bytes = kdf.deriveKey(5);

	// generate a new RC2 key spec
	SecretKeySpec rc2KeySpec = new SecretKeySpec(rc2Bytes, "RC2");

	// convert the RC2 key spec into an RC2 key
	SecretKey rc2Key;
	try {
	    rc2Key = rc2KeyFactory.generateSecret(rc2KeySpec);
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
	ModeParameterSpec iv = new ModeParameterSpec(ivBytes);

	// initialize the RC2 cipher
	cipher.initDecrypt(rc2Key, iv, null);
    }

}
