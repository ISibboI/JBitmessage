/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group, Technische Universitaet
 * Darmstadt
 * 
 * For conditions of usage and distribution please refer to the file COPYING in
 * the root directory of this package.
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
import de.flexiprovider.core.kdf.PBKDF1;

/**
 * This class implements passphrase based encryption (PBE) as defined in <a
 * href="http://www.rsasecurity.com/rsalabs/pkcs/pkcs-5/index.html">PKCS#5
 * version 2.0</a>. The key for the cipher (here DES) is derived from the
 * passphrase by applying a hashfunction (here
 * {@link de.flexiprovider.core.md.SHA1 SHA-1}) several times on it. Because we
 * don't provide single DES, {@link de.flexiprovider.core.desede.DESede DESede}
 * with the same key for encryption, decryption, encryption is used instead.
 * 
 * @author Thomas Wahrenbruch
 */
public class PBEWithSHA1AndDES_CBC extends PBES1 {

    /**
     * The OID of PBEWithSHA1AndDES_CBC.
     */
    public static final String OID = "1.2.840.113549.1.5.10";

    // SecretKeyFactory for the tranformation DESKeySpec -> DESKey
    private SecretKeyFactory desKeyFactory;

    /**
     * The default constructor tries to initialize the message digest, the
     * secret key factory and the cipher.
     */
    public PBEWithSHA1AndDES_CBC() {
	// a little trick: since we don't provide single DES,
	// we take DESede with the same key for each round.
	cipher = new DESede.DESede_CBC();
	try {
	    cipher.setPadding("PKCS5Padding");
	} catch (NoSuchPaddingException nspe) {
	    throw new RuntimeException("PKCS #5 padding not found");
	}
	desKeyFactory = new DESedeKeyFactory();
	kdf = new PBKDF1.SHA1();
    }

    /**
     * @return the name of this cipher
     */
    public String getName() {
	return "PbeWithSHA1AndDES_CBC";
    }

    /**
     * Returns the key size of the given key object. Since the cipher underlying
     * this PBE scheme is DES, we always return 56 as the effective key size if
     * the key is valid.
     * 
     * @param key
     *                the key object
     * @return the key size of the given key object.
     * @throws InvalidKeyException
     *                 if key is not an instance of <tt>PBEKey</tt>
     */
    public int getKeySize(Key key) throws InvalidKeyException {
	if (key instanceof PBEKey) {
	    return 56;
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

	// generate the key bytes for the DES key and the IV
	kdf.init(pbeKey, pbeParamSpec);
	byte[] keyBytes = kdf.deriveKey(16);

	// copy the key bytes 3x into an array
	byte[] desBytes = new byte[24];
	System.arraycopy(keyBytes, 0, desBytes, 0, 8);
	System.arraycopy(keyBytes, 0, desBytes, 8, 8);
	System.arraycopy(keyBytes, 0, desBytes, 16, 8);

	// generate a DESede key spec
	DESedeKeySpec desKeySpec = new DESedeKeySpec(desBytes);
	// convert the DESedeKeySpec into a DESKey
	SecretKey desKey;
	try {
	    desKey = desKeyFactory.generateSecret(desKeySpec);
	} catch (InvalidKeySpecException ikse) {
	    // the key spec is correct and must be accepted
	    throw new RuntimeException("internal error");
	}

	// generate the IV
	ModeParameterSpec modeParams = new ModeParameterSpec(keyBytes, 8, 8);

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

	// generate the key bytes for the DES key and the IV
	kdf.init(pbeKey, pbeParamSpec);
	byte[] keyBytes = kdf.deriveKey(16);

	// copy the key bytes 3x into an array
	byte[] desBytes = new byte[24];
	System.arraycopy(keyBytes, 0, desBytes, 0, 8);
	System.arraycopy(keyBytes, 0, desBytes, 8, 8);
	System.arraycopy(keyBytes, 0, desBytes, 16, 8);

	// generate a DESede key spec
	DESedeKeySpec desKeySpec = new DESedeKeySpec(desBytes);
	// convert the DESedeKeySpec into a DESKey
	SecretKey desKey;
	try {
	    desKey = desKeyFactory.generateSecret(desKeySpec);
	} catch (InvalidKeySpecException ikse) {
	    // the key spec is correct and must be accepted
	    throw new RuntimeException("internal error");
	}

	// generate the IV
	ModeParameterSpec modeParams = new ModeParameterSpec(keyBytes, 8, 8);

	// initialize the DESede cipher
	cipher.initDecrypt(desKey, modeParams, (AlgorithmParameterSpec) null);
    }

}
