/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */
package de.flexiprovider.common.ies;

import java.io.ByteArrayOutputStream;

import de.flexiprovider.api.AsymmetricHybridCipher;
import de.flexiprovider.api.BlockCipher;
import de.flexiprovider.api.KeyAgreement;
import de.flexiprovider.api.KeyDerivation;
import de.flexiprovider.api.Mac;
import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.exceptions.BadPaddingException;
import de.flexiprovider.api.exceptions.IllegalBlockSizeException;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.exceptions.InvalidKeySpecException;
import de.flexiprovider.api.keys.Key;
import de.flexiprovider.api.keys.KeyPair;
import de.flexiprovider.api.keys.PrivateKey;
import de.flexiprovider.api.keys.PublicKey;
import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.api.keys.SecretKeyFactory;
import de.flexiprovider.api.keys.SecretKeySpec;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.util.ByteUtils;
import de.flexiprovider.core.kdf.KDF2;
import de.flexiprovider.core.kdf.KDFParameterSpec;

/**
 * The <i>Integrated Encryption Scheme</i> (IES) is an encryption scheme based
 * on a key agreement scheme using an ephemeral key pair, a symmetric cipher,
 * and a message authentication code (MAC) to encrypt and decrypt data. IES is
 * described in IEEE 1363a-2004.
 * 
 * @author Marcus Stögbauer
 * @author Hristo Indzhov
 * @author Martin Döring
 */
public abstract class IES extends AsymmetricHybridCipher {

    /**
     * the source of randomness
     */
    protected SecureRandom random;

    // the public key used for encryption
    private PublicKey pubKey;

    // the private key used for decryption
    private PrivateKey privKey;

    // the IES parameters
    private IESParameterSpec iesParams;

    // flag indicating the IES mode (internal (XOR) or symmetric cipher)
    private boolean isInternal = false;

    // the name of the symmetric cipher
    private String symCipherName;

    // the instantiated symmetric cipher for symmetric cipher mode
    private BlockCipher symCipher;

    /**
     * The algorithm parameters obtained from the (private or public) key.
     */
    protected AlgorithmParameterSpec keyParams;

    // the derived symmetric key
    private SecretKey symKey;

    // the length of the symmetric cipher key
    private int symKeyLength;

    // MAC function name
    private String macName;

    // the MAC instance
    private Mac mac;

    // the key factory for the MAC
    private SecretKeyFactory macKF;

    // the MAC length
    private int macLen;

    // the MAC encoding parameters
    private byte[] macEncParams;

    // the shared data for the key agreement
    private byte[] sharedData;

    // the key agreement module
    private KeyAgreement kag;

    // the key derivation function
    private KeyDerivation kdf;

    // the ephemeral public key
    private PublicKey ephPubKey;

    // the ephemeral private key
    private PrivateKey ephPrivKey;

    // the size of the encoded ephemeral public key
    private int encEphPubKeySize;

    // the cipher mode we are in (Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE)
    private int opMode;

    // buffer to store the input data
    private ByteArrayOutputStream buf;

    /**
     * Constructor.
     */
    protected IES() {
	buf = new ByteArrayOutputStream();
	kag = getKeyAgreement();
	kdf = new KDF2();
    }

    /**
     * Continue a multiple-part encryption or decryption operation.
     * 
     * @param input
     *                byte array containing the next part of the input
     * @param inOff
     *                index in the array where the input starts
     * @param inLen
     *                length of the input
     * @return the processed byte array.
     */
    public byte[] update(byte[] input, int inOff, int inLen) {
	if (input != null) {
	    buf.write(input, inOff, inLen);
	}
	return new byte[0];
    }

    /**
     * Encrypts or decrypts data in a single-part operation, or finishes a
     * multiple-part operation. The data is encrypted or decrypted, depending on
     * how this cipher was initialized.
     * 
     * @param input
     *                the input buffer
     * @param inOff
     *                the offset in input where the input starts
     * @param inLen
     *                the input length
     * @return the new buffer with the result
     * @throws BadPaddingException
     *                 if this cipher is in decryption mode, and (un)padding has
     *                 been requested, but the decrypted data is not bounded by
     *                 the appropriate padding bytes
     */
    public byte[] doFinal(byte[] input, int inOff, int inLen)
	    throws BadPaddingException {
	update(input, inOff, inLen);
	byte[] data = buf.toByteArray();
	buf.reset();
	if (opMode == ENCRYPT_MODE) {
	    return messageEncrypt(data);
	} else if (opMode == DECRYPT_MODE) {
	    return messageDecrypt(data);
	}
	return null;
    }

    /**
     * Initialize the cipher with a key and parameters for data encryption. The
     * parameters have to be an instance of {@link IESParameterSpec}.
     * 
     * @param key
     *                the key
     * @param params
     *                the parameters
     * @param random
     *                the source of randomness
     * @throws InvalidKeyException
     *                 if the key is inappropriate.
     * @throws InvalidAlgorithmParameterException
     *                 if the parameters are not an instance of
     *                 {@link IESParameterSpec} or the ephemeral key pair stored
     *                 in the parameters is invalid.
     */
    protected void initCipherEncrypt(Key key, AlgorithmParameterSpec params,
	    SecureRandom random) throws InvalidKeyException,
	    InvalidAlgorithmParameterException {

	pubKey = checkPubKey(key);
	iesParams = checkParameters(params);

	// obtain the ephemeral key pair
	KeyPair ephKeyPair = iesParams.getEphKeyPair();
	// if it is null
	if (ephKeyPair == null) {
	    // generate it
	    ephKeyPair = generateEphKeyPair();
	    // and assign the keys
	    ephPubKey = ephKeyPair.getPublic();
	    ephPrivKey = ephKeyPair.getPrivate();
	} else {
	    // check and assign the keys contained in the key pair
	    ephPubKey = checkPubKey(ephKeyPair.getPublic());
	    ephPrivKey = checkPrivKey(ephKeyPair.getPrivate());
	}
	// compute the size of the encoded ephemeral public key
	encEphPubKeySize = getEncEphPubKeySize();

	symCipherName = iesParams.getSymCipherName();
	sharedData = iesParams.getSharedInfo();

	isInternal = symCipherName == null;
	if (!isInternal) {
	    initSymCipher();
	}
	initMAC();

	this.random = (random != null) ? random : Registry.getSecureRandom();
	opMode = ENCRYPT_MODE;
    }

    /**
     * Initialize the cipher with a certain key for data encryption.
     * 
     * @param key
     *                the key
     * @param params
     *                the algorithm parameters
     * @throws InvalidKeyException
     *                 if the given key is inappropriate for initializing this
     *                 cipher.
     * @throws InvalidAlgorithmParameterException
     *                 if the given parameters are inappropriate for
     *                 initializing this cipher.
     */
    protected void initCipherDecrypt(Key key, AlgorithmParameterSpec params)
	    throws InvalidKeyException, InvalidAlgorithmParameterException {

	privKey = checkPrivKey(key);
	iesParams = checkParameters(params);

	symCipherName = iesParams.getSymCipherName();
	sharedData = iesParams.getSharedInfo();

	isInternal = symCipherName == null;
	if (!isInternal) {
	    initSymCipher();
	}

	encEphPubKeySize = getEncEphPubKeySize();
	initMAC();

	opMode = DECRYPT_MODE;
    }

    protected int decryptOutputSize(int inLen) {
	// TODO integrate correct computation
	return 0;
    }

    protected int encryptOutputSize(int inLen) {
	// TODO integrate correct computation
	return 0;
    }

    /**
     * Encrypt the plaintext stored in input. The method should also perform an
     * additional length check.
     * 
     * @param input
     *                the plaintext to be encrypted
     * @return the encrypted message
     * @throws BadPaddingException
     *                 if encryption fails.
     */
    protected byte[] messageEncrypt(byte[] input) throws BadPaddingException {

	// generate key stream
	byte[] keyStream = generateKeyStream(ephPrivKey, pubKey, input.length);

	// symmetrically encrypt the plaintext
	byte[] cText;
	try {
	    cText = processMessage(keyStream, input);
	} catch (Exception e) {
	    throw new BadPaddingException(e.getMessage());
	}

	// compute MAC tag
	byte[] macTag = generateMAC(keyStream, cText);

	// pack output
	return packCiphertext(cText, macTag);
    }

    /**
     * Decrypt the ciphertext stored in input. If MAC verification fails,
     * <tt>null</tt> is returned.
     * 
     * @param input
     *                the message to be decrypted
     * @return the decrypted ciphertext
     * @throws BadPaddingException
     *                 if the ciphertext is invalid.
     */
    protected byte[] messageDecrypt(byte[] input) throws BadPaddingException {

	// unpack the IES ciphertext ...
	byte[][] cm = unpackCiphertext(input);
	// ... and obtain the symmetric ciphertext ...
	byte[] cText = cm[0];
	// ... and the MAC tag
	byte[] macTag = cm[1];

	// generate key stream
	byte[] keyStream = generateKeyStream(privKey, ephPubKey, cText.length);

	// compute MAC tag
	byte[] newMacTag = generateMAC(keyStream, cText);
	// check if MAC tags match
	if (!ByteUtils.equals(macTag, newMacTag)) {
	    throw new BadPaddingException("invalid ciphertext");
	}

	try {
	    // symmetrically decrypt the ciphertext and return
	    return processMessage(keyStream, cText);
	} catch (IllegalBlockSizeException e) {
	    throw new BadPaddingException("invalid ciphertext");
	}
    }

    /**
     * Check whether the given parameters are of the correct type. If so, return
     * the checked parameters. If not, throw an
     * {@link InvalidAlgorithmParameterException}.
     * 
     * @param params
     *                the parameters to be checked
     * @return the checked parameters
     * @throws InvalidAlgorithmParameterException
     *                 if the parameters are inappropriate.
     */
    private IESParameterSpec checkParameters(AlgorithmParameterSpec params)
	    throws InvalidAlgorithmParameterException {

	// if the parameters are null
	if (params == null) {
	    // return the default parameters
	    return new IESParameterSpec();
	}

	// check if the parameters are of the correct type
	if (!(params instanceof IESParameterSpec)) {
	    throw new InvalidAlgorithmParameterException("unsupported type");
	}

	// return the checked parameters
	return (IESParameterSpec) params;
    }

    /**
     * If the cipher uses a symmetric cipher for encryption or decryption,
     * instantiate and assign the symmetric cipher object to <tt>symCipher</tt>.
     */
    private void initSymCipher() {
	try {
	    symCipher = Registry.getBlockCipher(symCipherName);
	} catch (Exception ex) {
	    throw new RuntimeException("IES Init (checkSymCipher): "
		    + ex.getMessage());
	}
	symKeyLength = iesParams.getSymKeyLength();
    }

    /**
     * Initialize the MAC function object. Try to instantiate the MAC function
     * with name <tt>macName</tt> and set <tt>macLen</tt>.
     */
    private void initMAC() {
	macName = iesParams.getMacName();
	try {
	    mac = Registry.getMAC(macName);
	    macKF = Registry.getSecretKeyFactory(iesParams.getMacKFName());
	} catch (Exception ex) {
	    throw new RuntimeException("IES Init (checkMac): "
		    + ex.getMessage());
	}
	macLen = mac.getMacLength();
	macEncParams = iesParams.getMacEncParam();
    }

    /**
     * Generate the key stream used for encryption and decryption.
     * 
     * @param privKey
     *                the private key used for the key agreement
     * @param pubKey
     *                the public key used for the key agreement
     * @param len
     *                the desired length of the key stream
     * @return the key stream
     */
    private byte[] generateKeyStream(PrivateKey privKey, PublicKey pubKey,
	    int len) {

	int tLen = (isInternal ? len : symKeyLength) + macLen;

	try {
	    // use key agreement to obtain secret key
	    kag.init(privKey, null, random);
	    byte[] secretKey = kag.doPhase(pubKey, true).getEncoded();

	    // generate key stream with the key derivation function
	    KDFParameterSpec kdfParams = new KDFParameterSpec(sharedData);
	    kdf.init(secretKey, kdfParams);
	    byte[] keyStream = kdf.deriveKey(tLen);

	    if (!isInternal) {
		byte[] symKeyData = new byte[symKeyLength];
		System.arraycopy(keyStream, 0, symKeyData, 0, symKeyLength);
		SecretKeyFactory symKeyFactory = Registry
			.getSecretKeyFactory(iesParams.getSymKFName());
		SecretKeySpec keySpec = new SecretKeySpec(symKeyData,
			symCipherName);
		symKey = symKeyFactory.generateSecret(keySpec);
		if (opMode == ENCRYPT_MODE) {
		    symCipher.initEncrypt(symKey, random);
		} else if (opMode == DECRYPT_MODE) {
		    symCipher.initDecrypt(symKey);
		}
	    }

	    return keyStream;

	} catch (Exception e) {
	    throw new RuntimeException("internal error");
	}
    }

    /**
     * Encrypt or decrypt a message via XOR when in internal mode or via the
     * symmetric cipher <tt>symCipher</tt> when in symmetric cipher mode.
     * 
     * @param keyStream
     *                the key stream generated with <tt>genKeyStream()</tt>
     * @param message
     *                the message
     * @return encrypted or decrypted message
     * @throws BadPaddingException
     *                 during encryption if the ciphertext is invalid.
     * @throws IllegalBlockSizeException
     *                 during encryption if the ciphertext is invalid.
     */
    private byte[] processMessage(byte[] keyStream, byte[] message)
	    throws IllegalBlockSizeException, BadPaddingException {

	byte[] result;
	if (isInternal) {
	    result = new byte[message.length];
	    for (int i = message.length - 1; i >= 0; i--) {
		result[i] = (byte) (message[i] ^ keyStream[i]);
	    }
	} else {
	    result = symCipher.doFinal(message);
	}

	return result;
    }

    /**
     * Generate the MAC tag.
     * <p>
     * Create an <tt>HMacKey</tt> object from the <tt>keyStream</tt> and
     * initializes the MAC function with it. If there are some MAC encoding
     * parameters they are appended to the ciphertext and finally the MAC
     * function is called.
     * 
     * @param keyStream
     *                the key stream generated with <tt>genKeyStream()</tt>
     * @param cText
     *                the ciphertext
     * @return MAC tag
     */
    private byte[] generateMAC(byte[] keyStream, byte[] cText) {

	int macKeyLen = isInternal ? cText.length : symKeyLength;

	byte[] macKeyStream = new byte[keyStream.length - macKeyLen];
	System.arraycopy(keyStream, macKeyLen, macKeyStream, 0,
		macKeyStream.length);

	// initialize the MAC function with a MAC key
	SecretKeySpec macKeySpec = new SecretKeySpec(macKeyStream, macName);
	SecretKey macKey;
	try {
	    macKey = macKF.generateSecret(macKeySpec);
	    mac.init(macKey);
	} catch (InvalidKeySpecException e) {
	    throw new RuntimeException("internal error");
	} catch (InvalidKeyException ike) {
	    throw new RuntimeException("InvalidKeyException: "
		    + ike.getMessage());
	}

	macKeyLen = cText.length;
	byte[] macInput = cText;
	// if MAC encoding parameter is specified, append it to the
	// encrypted message and call the function
	if (macEncParams != null) {
	    macInput = new byte[macKeyLen + macEncParams.length];
	    System.arraycopy(cText, 0, macInput, 0, macKeyLen);
	    System.arraycopy(macEncParams, 0, macInput, macKeyLen,
		    macEncParams.length);
	}
	byte[] macTag = mac.doFinal(macInput);

	return macTag;

    }

    /**
     * Pack the IES ciphertext as
     * <tt>(encoded ephemeral public key || symmetric ciphertext || MAC tag)</tt>.
     * 
     * @param cText
     *                the ciphertext
     * @param macTag
     *                the MAC tag
     * @return the packed output
     */
    private byte[] packCiphertext(byte[] cText, byte[] macTag) {
	byte[] result = new byte[encEphPubKeySize + cText.length + macLen];
	byte[] encEphPubKey = encodeEphPubKey(ephPubKey);

	System.arraycopy(encEphPubKey, 0, result, 0, encEphPubKeySize);
	System.arraycopy(cText, 0, result, encEphPubKeySize, cText.length);
	System.arraycopy(macTag, 0, result, encEphPubKeySize + cText.length,
		macLen);

	return result;
    }

    /**
     * Unpack the IES ciphertext into the ephemeral public key, ciphertext, and
     * MAC tag.
     * 
     * @param input
     *                the IES ciphertext
     * @return the symmetric ciphertext and the MAC tag
     */
    private byte[][] unpackCiphertext(byte[] input) {
	int cLen = input.length - encEphPubKeySize - macLen;
	byte[] encEphPubKey = new byte[encEphPubKeySize];
	byte[] cText = new byte[cLen];
	byte[] macTag = new byte[macLen];

	System.arraycopy(input, 0, encEphPubKey, 0, encEphPubKeySize);
	System.arraycopy(input, encEphPubKeySize, cText, 0, cLen);
	System.arraycopy(input, encEphPubKeySize + cLen, macTag, 0, macLen);

	ephPubKey = decodeEphPubKey(encEphPubKey);

	return new byte[][] { cText, macTag };
    }

    /**
     * Check whether the given encryption key is of the correct type. If so, set
     * the key parameters and return the checked key. If not, throw an
     * {@link InvalidKeyException}.
     * 
     * @param key
     *                the key to be checked
     * @return the checked key
     * @throws InvalidKeyException
     *                 if the given key is inappropriate.
     */
    protected abstract PublicKey checkPubKey(Key key)
	    throws InvalidKeyException;

    /**
     * Check whether the given decryption key is of the correct type. If so, set
     * the key parameters and return the checked key. If not, throw an
     * {@link InvalidKeyException}.
     * 
     * @param key
     *                the key to be checked
     * @return the checked key
     * @throws InvalidKeyException
     *                 if the given key is inappropriate.
     */
    protected abstract PrivateKey checkPrivKey(Key key)
	    throws InvalidKeyException;

    /**
     * Instantiate and return the key agreement module.
     * 
     * @return the key agreement module
     */
    protected abstract KeyAgreement getKeyAgreement();

    /**
     * Generate an ephemeral key pair. This method is used in case no ephemeral
     * key pair is specified via the {@link IESParameterSpec} during
     * initialization.
     * 
     * @return the generated ephemeral key pair
     */
    protected abstract KeyPair generateEphKeyPair();

    /**
     * Encode the ephemeral public key.
     * 
     * @param ephPubKey
     *                the ephemeral public key
     * @return the encoded key
     */
    protected abstract byte[] encodeEphPubKey(PublicKey ephPubKey);

    /**
     * Compute and return the size (in bytes) of the encoded ephemeral public
     * key.
     * 
     * @return the size of the encoded ephemeral public key
     */
    protected abstract int getEncEphPubKeySize();

    /**
     * Decode the ephemeral public key.
     * 
     * @param encEphPubKey
     *                the encoded ephemeral public key
     * @return the decoded key
     */
    protected abstract PublicKey decodeEphPubKey(byte[] encEphPubKey);

}
