/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group, Technische Universitaet
 * Darmstadt
 * 
 * For conditions of usage and distribution please refer to the file COPYING in
 * the root directory of this package.
 * 
 */

package de.flexiprovider.core.pbe;

import de.flexiprovider.api.BlockCipher;
import de.flexiprovider.api.Cipher;
import de.flexiprovider.api.KeyDerivation;
import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.exceptions.BadPaddingException;
import de.flexiprovider.api.exceptions.IllegalBlockSizeException;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.exceptions.InvalidKeySpecException;
import de.flexiprovider.api.exceptions.InvalidParameterSpecException;
import de.flexiprovider.api.exceptions.NoSuchAlgorithmException;
import de.flexiprovider.api.exceptions.NoSuchModeException;
import de.flexiprovider.api.exceptions.NoSuchPaddingException;
import de.flexiprovider.api.exceptions.ShortBufferException;
import de.flexiprovider.api.keys.Key;
import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.api.keys.SecretKeyFactory;
import de.flexiprovider.api.keys.SecretKeySpec;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.api.parameters.AlgorithmParameters;
import de.flexiprovider.core.kdf.PBKDF2;
import de.flexiprovider.core.kdf.PBKDF2ParameterSpec;
import de.flexiprovider.pki.AlgorithmIdentifier;

/**
 * This class is the main class for the passphrase based encryption scheme 2 as
 * defined in <a
 * href="http://www.rsasecurity.com/rsalabs/pkcs/pkcs-5/index.html">PKCS #5
 * version 2.0</a> standard.
 * 
 * @author Thomas Wahrenbruch
 * @author Martin Döring
 */
public class PBES2 extends Cipher {

    /**
     * The OID of PBES2.
     */
    public static final String OID = "1.2.840.113549.1.5.13";

    // the underlying block cipher
    private BlockCipher cipher;

    // the key derivation function
    private KeyDerivation kdf;

    /**
     * Return the name of this cipher.
     * 
     * @return "PBES2"
     */
    public String getName() {
	return "PBES2";
    }

    /**
     * Return the key size of the given key object. Checks whether the key
     * object is an instance of <tt>PBEKey</tt>.
     * 
     * @param key
     *                the key object
     * @return the key size of the given key object.
     * @throws InvalidKeyException
     *                 if key is invalid.
     */
    public int getKeySize(Key key) throws InvalidKeyException {
	if (!(key instanceof PBEKey)) {
	    throw new InvalidKeyException("unsupported type");
	}
	return key.getEncoded().length << 3;
    }

    /**
     * Returns the block size (in bytes).
     * 
     * @return the block size (in bytes), or 0 if the underlying algorithm is
     *         not a block cipher
     */
    public int getBlockSize() {
	return cipher.getBlockSize();
    }

    /**
     * Returns the initialization vector (IV) in a new buffer.
     * <p>
     * This is useful in the context of password-based encryption or decryption,
     * where the IV is derived from a user-provided passphrase.
     * 
     * @return the initialization vector in a new buffer, or null if the
     *         underlying algorithm does not use an IV, or if the IV has not yet
     *         been set.
     */
    public byte[] getIV() {
	return cipher.getIV();
    }

    /**
     * Returns the length in bytes that an output buffer would need to be in
     * order to hold the result of the next update or doFinal operation, given
     * the input length inputLen (in bytes).
     * <p>
     * This call takes into account any unprocessed (buffered) data from a
     * previous update call, and padding.
     * <p>
     * The actual output length of the next update or doFinal call may be
     * smaller than the length returned by this method.
     * 
     * @param inputLen
     *                the input length (in bytes)
     * @return the required output buffer size (in bytes)
     */
    public int getOutputSize(int inputLen) {
	return cipher.getOutputSize(inputLen);
    }

    /**
     * Returns the parameters used with this cipher.
     * <p>
     * The returned parameters may be the same that were used to initialize this
     * cipher, or may contain the default set of parameters or a set of randomly
     * generated parameters used by the underlying cipher implementation
     * (provided that the underlying cipher implementation uses a default set of
     * parameters or creates new parameters if it needs parameters but was not
     * initialized with any).
     * 
     * @return the parameters used with this cipher, or null if this cipher does
     *         not use any parameters.
     */
    public AlgorithmParameterSpec getParameters() {
	return cipher.getParameters();
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

	if (!(params instanceof PBES2ParameterSpec)) {
	    throw new InvalidAlgorithmParameterException("unsupported type");
	}
	PBES2ParameterSpec pbe2Params = (PBES2ParameterSpec) params;

	// extract prf name from pbe2params
	AlgorithmIdentifier kdfAid = pbe2Params.getKeyDerivationFunction();
	String kdfOID = kdfAid.getAlgorithmOID().toString();
	String expKDF2OID = "1.2.840.113549.1.5.12";
	// check if requested kdf == expected (supported) kdf
	if (!kdfOID.equals(expKDF2OID)) {
	    throw new InvalidAlgorithmParameterException(
		    "unsupported key derivation function");
	}

	// extract prf parameters from pbe2params
	PBKDF2ParameterSpec kdfParams;
	try {
	    // get parameters
	    AlgorithmParameters algKdfParams = kdfAid.getParams();
	    // get parameter specification
	    kdfParams = (PBKDF2ParameterSpec) algKdfParams
		    .getParameterSpec(PBKDF2ParameterSpec.class);
	} catch (InvalidParameterSpecException e) {
	    throw new InvalidAlgorithmParameterException(
		    "InvalidParameterSpecException: " + e.getMessage());
	} catch (NoSuchAlgorithmException e) {
	    throw new InvalidAlgorithmParameterException(
		    "NoSuchAlgorithmException: " + e.getMessage());
	}

	kdf = new PBKDF2();

	// check key type
	if (!(key instanceof PBEKey)) {
	    throw new InvalidKeyException("unsupported key type");
	}

	// PBEKey => Cipher key
	kdf.init(key.getEncoded(), kdfParams);
	byte[] uKeyBytes = kdf.deriveKey(kdfParams.getKeySize());

	// extract cipher name from pbe2params
	AlgorithmIdentifier cipherAid = pbe2Params.getEncryptionScheme();
	String cipherOID = cipherAid.getAlgorithmOID().toString();

	// generate cipher specific key with the SecretKeyFactory
	SecretKey uKey = null;
	try {
	    SecretKeySpec uKeySpec = new SecretKeySpec(uKeyBytes, cipherOID);
	    SecretKeyFactory skf = Registry.getSecretKeyFactory(cipherOID);
	    uKey = skf.generateSecret(uKeySpec);
	} catch (NoSuchAlgorithmException nsae) {
	    throw new InvalidAlgorithmParameterException(nsae.getMessage());
	} catch (InvalidKeySpecException ikse) {
	    throw new InvalidAlgorithmParameterException(ikse.getMessage());
	}

	// generate cipher specific parameters with the AlgorithmParameters
	AlgorithmParameterSpec paramSpec = null;
	try {
	    AlgorithmParameters cipherap = cipherAid.getParams();
	    Class paramSpecClass = Registry.getAlgParamSpecClass(cipherOID);
	    paramSpec = cipherap.getParameterSpec(paramSpecClass);
	} catch (NoSuchAlgorithmException e) {
	    // this is OK, if no parameters are registered, cipher is
	    // initialized with null parameters
	} catch (InvalidParameterSpecException e) {
	    // this is not OK, if parameters are registered, everything
	    // should work
	    throw new InvalidAlgorithmParameterException(e.getMessage());
	}

	try {
	    // get cipher object
	    cipher = Registry.getBlockCipher(cipherOID);
	} catch (NoSuchAlgorithmException nsae) {
	    throw new InvalidAlgorithmParameterException(
		    "did not find block cipher '" + nsae.getMessage() + "'");
	} catch (NoSuchPaddingException nspe) {
	    throw new InvalidAlgorithmParameterException(
		    "NoSuchPaddingException: " + nspe.getMessage());
	}

	// init cipher
	cipher.initEncrypt(uKey, paramSpec, random);
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

	if (!(params instanceof PBES2ParameterSpec)) {
	    throw new InvalidAlgorithmParameterException("unsupported type");
	}
	PBES2ParameterSpec pbe2Params = (PBES2ParameterSpec) params;

	// extract prf name from pbe2params
	AlgorithmIdentifier kdfAid = pbe2Params.getKeyDerivationFunction();
	String kdfOID = kdfAid.getAlgorithmOID().toString();
	String expKDF2OID = "1.2.840.113549.1.5.12";
	// check if requested kdf == expected (supported) kdf
	if (!kdfOID.equals(expKDF2OID)) {
	    throw new InvalidAlgorithmParameterException(
		    "unsupported key derivation function");
	}

	// extract prf parameters from pbe2params
	PBKDF2ParameterSpec kdfParams;
	try {
	    // get parameters
	    AlgorithmParameters algKdfParams = kdfAid.getParams();
	    // get parameter specification
	    kdfParams = (PBKDF2ParameterSpec) algKdfParams
		    .getParameterSpec(PBKDF2ParameterSpec.class);
	} catch (InvalidParameterSpecException e) {
	    throw new InvalidAlgorithmParameterException(
		    "InvalidParameterSpecException: " + e.getMessage());
	} catch (NoSuchAlgorithmException e) {
	    throw new InvalidAlgorithmParameterException(
		    "NoSuchAlgorithmException: " + e.getMessage());
	}

	kdf = new PBKDF2();

	// check key type
	if (!(key instanceof PBEKey)) {
	    throw new InvalidKeyException("unsupported key type");
	}

	// PBEKey => Cipher key
	kdf.init(key.getEncoded(), kdfParams);
	byte[] uKeyBytes = kdf.deriveKey(kdfParams.getKeySize());

	// extract cipher name from pbe2params
	AlgorithmIdentifier cipherAid = pbe2Params.getEncryptionScheme();
	String cipherOID = cipherAid.getAlgorithmOID().toString();

	// generate cipher specific key with the SecretKeyFactory
	SecretKey uKey = null;
	try {
	    SecretKeySpec uKeySpec = new SecretKeySpec(uKeyBytes, cipherOID);
	    SecretKeyFactory skf = Registry.getSecretKeyFactory(cipherOID);
	    uKey = skf.generateSecret(uKeySpec);
	} catch (NoSuchAlgorithmException nsae) {
	    throw new InvalidAlgorithmParameterException(nsae.getMessage());
	} catch (InvalidKeySpecException ikse) {
	    throw new InvalidAlgorithmParameterException(ikse.getMessage());
	}

	// generate cipher specific parameters with the AlgorithmParameters
	AlgorithmParameterSpec paramSpec = null;
	try {
	    AlgorithmParameters cipherap = cipherAid.getParams();
	    Class paramSpecClass = Registry.getAlgParamSpecClass(cipherOID);
	    paramSpec = cipherap.getParameterSpec(paramSpecClass);
	} catch (NoSuchAlgorithmException e) {
	    // this is OK, if no parameters are registered, cipher is
	    // initialized with null parameters
	} catch (InvalidParameterSpecException e) {
	    // this is not OK, if parameters are registered, everything
	    // should work
	    throw new InvalidAlgorithmParameterException(e.getMessage());
	}

	try {
	    // get cipher object
	    cipher = Registry.getBlockCipher(cipherOID);
	} catch (NoSuchAlgorithmException nsae) {
	    throw new InvalidAlgorithmParameterException(
		    "did not find block cipher '" + nsae.getMessage() + "'");
	} catch (NoSuchPaddingException nspe) {
	    throw new InvalidAlgorithmParameterException(
		    "NoSuchPaddingException: " + nspe.getMessage());
	}

	// init cipher
	cipher.initDecrypt(uKey, paramSpec);
    }

    /**
     * Set the mode for this cipher. This method is not supported and always
     * throws an exception.
     * 
     * @param modeName
     *                the name of the cipher mode
     * @throws NoSuchModeException
     *                 always.
     */
    protected void setMode(String modeName) throws NoSuchModeException {
	throw new NoSuchModeException("unsupported");
    }

    /**
     * Set the padding scheme for this cipher. This method is not supported and
     * always throws an exception.
     * 
     * @param paddingName
     *                the name of the padding scheme
     * @throws NoSuchPaddingException
     *                 always.
     */
    protected void setPadding(String paddingName) throws NoSuchPaddingException {
	throw new NoSuchPaddingException("not supported");
    }

    /**
     * Continue a multiple-part encryption or decryption operation (depending on
     * how this cipher was initialized), processing another data part.
     * 
     * @param input
     *                the input buffer
     * @param inOff
     *                the offset where the input starts
     * @param inLen
     *                the input length
     * @return a new buffer with the result (maybe an empty byte array)
     */
    public byte[] update(byte[] input, int inOff, int inLen) {
	return cipher.update(input, inOff, inLen);
    }

    /**
     * Continue a multiple-part encryption or decryption operation (depending on
     * how this cipher was initialized), processing another data part.
     * 
     * @param input
     *                the input buffer
     * @param inOff
     *                the offset where the input starts
     * @param inLen
     *                the input length
     * @param output
     *                the output buffer
     * @param outOff
     *                the offset where the result is stored
     * @return the length of the output
     * @throws ShortBufferException
     *                 if the output buffer is too small to hold the result.
     */
    public int update(byte[] input, int inOff, int inLen, byte[] output,
	    int outOff) throws ShortBufferException {
	return cipher.update(input, inOff, inLen, output, outOff);
    }

    /**
     * Finish a multiple-part encryption or decryption operation (depending on
     * how this cipher was initialized).
     * 
     * @param input
     *                the input buffer
     * @param inOff
     *                the offset where the input starts
     * @param inLen
     *                the input length
     * @return a new buffer with the result
     * @throws IllegalBlockSizeException
     *                 if the total input length is not a multiple of the block
     *                 size (for encryption when no padding is used or for
     *                 decryption).
     * @throws BadPaddingException
     *                 if unpadding fails.
     */
    public byte[] doFinal(byte[] input, int inOff, int inLen)
	    throws IllegalBlockSizeException, BadPaddingException {
	return cipher.doFinal(input, inOff, inLen);
    }

    /**
     * Finish a multiple-part encryption or decryption operation (depending on
     * how this cipher was initialized).
     * 
     * @param input
     *                the input buffer
     * @param inOff
     *                the offset where the input starts
     * @param inLen
     *                the input length
     * @param output
     *                the buffer for the result
     * @param outOff
     *                the offset where the result is stored
     * @return the output length
     * @throws ShortBufferException
     *                 if the output buffer is too small to hold the result.
     * @throws IllegalBlockSizeException
     *                 if the total input length is not a multiple of the block
     *                 size (for encryption when no padding is used or for
     *                 decryption).
     * @throws BadPaddingException
     *                 if unpadding fails.
     */
    public int doFinal(byte[] input, int inOff, int inLen, byte[] output,
	    int outOff) throws ShortBufferException, IllegalBlockSizeException,
	    BadPaddingException {
	return cipher.doFinal(input, inOff, inLen, output, outOff);
    }

}
