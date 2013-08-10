/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.rsa;

import de.flexiprovider.api.AsymmetricBlockCipher;
import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.exceptions.BadPaddingException;
import de.flexiprovider.api.exceptions.IllegalBlockSizeException;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.keys.Key;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.core.rsa.interfaces.RSAKey;
import de.flexiprovider.core.rsa.interfaces.RSAPrivateCrtKey;
import de.flexiprovider.core.rsa.interfaces.RSAPrivateKey;
import de.flexiprovider.core.rsa.interfaces.RSAPublicKey;

/**
 * This class implements the RSAES-PKCS1-v1_5 algorithm as defined in <a
 * href=http://www.rsasecurity.com/rsalabs/node.asp?id=2125>PKCS#1 version 1.5</a>.
 * The class allows to encrypt messages with a public RSA key and to decrypt
 * with a private RSA key.
 * <p>
 * To encrypt a message, the following steps have to be performed:
 * 
 * <pre>
 * // The message to encrypt
 * String message = &quot;secret message&quot;;
 * byte[] messageBytes = message.getBytes();
 * 
 * // The source of randomness
 * SecureRandom secureRandom = Registry.getSecureRandom();
 * 
 * // Obtain a RSA_PKCS1_v1_5 Cipher Object
 * Cipher rsaCipher = Cipher.getInstance(&quot;RSA&quot;);
 * 
 * // Obtain the corresponding key pair generator
 * KeyPairGenerator rsaKPG = KeyPairGenerator.getInstance(&quot;RSA&quot;);
 * 
 * // Initialize the key pair generator with the desired strength
 * rsaKPG.initialize(1024);
 * 
 * // Generate a key pair
 * KeyPair rsaKeyPair = rsaKPG.genKeyPair();
 * 
 * // Initialize the cipher
 * // Note: if the public key has n with k(k - the length of n in octets) less than the 
 * // HEADER_SIZE of RSA_PKCS1_v1_5, a RuntimeException is thrown.
 * cipher.init(Cipher.ENCRYPT_MODE, rsaKeyPair.getPublic(), secureRandom);
 * 
 * // Finally encrypt the message
 * // If some of the PKCS1 functions fail during encryption, a RuntimeException is thrown.
 * byte[] ciphertextBytes = cipher.doFinal(messageBytes);
 * </pre>
 * 
 * To decrypt a ciphertext, the <tt>Cipher</tt> must be initialized with
 * <tt>Cipher.DECRYPT_MODE</tt> and the private key (<tt>rsaKeyPair.getPrivate()</tt>).
 * Decrypting, there are some special cases one should take in consideration:<br>
 * 1. If the length of the input is not equal to the maximum cipher text length.
 * A RuntimeException is thrown and the decryption is aborted.<br>
 * 2. If the length of the HEADER_SIZE is greater than the maximum cipher text
 * length. A RuntimeException is thrown and the decryption is aborted.<br>
 * 3. If the message has malformed header part. A RuntimeException is thrown and
 * the decryption is aborted.<br>
 * 
 * @author Thomas Wahrenbruch
 * @author Ralf-Philipp Weinmann
 * @author Hristo Indzhov
 */
public class RSA_PKCS1_v1_5 extends AsymmetricBlockCipher {

    /**
     * The OID of RSA_PKCS1_v1_5.
     */
    public static final String OID = "1.2.840.113549.1.1.1";

    // the size of the header (in bytes)
    private static final int HEADER_SIZE = 11;

    // source of randomness
    private SecureRandom secureRandom;

    // the blocktype (0x00 and 0x01 for private key operations, 0x02 for public
    // key operations)
    private byte blocktype;

    // the public key
    private RSAPublicKey pubKey;

    // the private key
    private RSAPrivateKey privKey;

    /**
     * @return the name of this cipher
     */
    public String getName() {
	return "RSA_PKCS1_v1_5";
    }

    /**
     * Return the key size of the given key object. Check whether the key object
     * is an instance of <tt>RSAKey</tt>. If so, return the bit length of the
     * modulus.
     * 
     * @param key
     *                the key object
     * @return the key size of the given key object.
     * @throws InvalidKeyException
     *                 if key is invalid.
     */
    public int getKeySize(Key key) throws InvalidKeyException {
	if (key instanceof RSAKey) {
	    return ((RSAKey) key).getN().bitLength();
	}
	throw new InvalidKeyException("RSA_PKCS1_v1_5: "
		+ "the key is not suitable for RSA the algorithm.");
    }

    /**
     * Initialize the cipher with an RSA public key for data encryption.
     * Parameters are currently not supported.
     * 
     * @param key
     *                the key to use for encryption
     * @param params
     *                the algorithm parameters
     * @param secureRandom
     *                the source of randomness
     * @throws InvalidKeyException
     *                 if the given key is inappropriate for initializing this
     *                 cipher.
     * @throws InvalidAlgorithmParameterException
     *                 if the bit length of the modulus is too small.
     */
    protected void initCipherEncrypt(Key key, AlgorithmParameterSpec params,
	    SecureRandom secureRandom) throws InvalidKeyException,
	    InvalidAlgorithmParameterException {

	if (!(key instanceof RSAPublicKey)) {
	    throw new InvalidKeyException("RSA_PKCS1_v1_5: "
		    + "the key is not suitable for RSA encryption.");
	}

	pubKey = (RSAPublicKey) key;
	blocktype = (byte) 0x02;
	this.secureRandom = (secureRandom != null) ? secureRandom : Registry
		.getSecureRandom();

	cipherTextSize = ((pubKey.getN().bitLength()) + 7) >> 3;
	maxPlainTextSize = cipherTextSize - HEADER_SIZE;

	if (maxPlainTextSize <= 0) {
	    throw new InvalidAlgorithmParameterException(
		    "Illegal modulus size.");
	}
    }

    /**
     * Initialize the cipher with an RSA private key for data decryption.
     * Parameters are currently not supported.
     * 
     * @param key
     *                the key to use for decryption
     * @param params
     *                the algorithm parameters
     * 
     * @throws InvalidKeyException
     *                 if the given key is inappropriate for initializing this
     *                 cipher.
     * @throws InvalidAlgorithmParameterException
     *                 if the bit length of the modulus is too small.
     */
    protected void initCipherDecrypt(Key key, AlgorithmParameterSpec params)
	    throws InvalidKeyException, InvalidAlgorithmParameterException {
	if (key instanceof RSAPrivateCrtKey || key instanceof RSAPrivateKey) {
	    privKey = (RSAPrivateKey) key;
	} else {
	    throw new InvalidKeyException("RSA_PKCS1_v1_5: "
		    + "the key is not suitable for RSA decryption.");
	}

	blocktype = (byte) 0x02;

	cipherTextSize = ((privKey.getN().bitLength()) + 7) >> 3;
	maxPlainTextSize = cipherTextSize - HEADER_SIZE;

	if (maxPlainTextSize <= 0) {
	    throw new InvalidAlgorithmParameterException(
		    "Illegal modulus size.");
	}
    }

    /**
     * Encrypt the plaintext stored in <tt>input</tt>.
     * 
     * @param input
     *                the plaintext
     * @return the cipher text as byte array
     * @throws BadPaddingException
     *                 if a PKCS1Exception is thrown by the encryption
     *                 primitive.
     */
    protected byte[] messageEncrypt(byte[] input) throws BadPaddingException {

	FlexiBigInt x = null;
	FlexiBigInt bigInt = null;
	int padLength = 0;
	int inLength = 0;
	byte[] cBytes = null;
	byte[] m = null;
	byte[] ps = null;

	// construct the message
	m = new byte[cipherTextSize];
	m[0] = 0x00;
	m[1] = blocktype;

	padLength = HEADER_SIZE - 3;
	inLength = input.length;

	// needs extra padding ?
	if (inLength < maxPlainTextSize) {
	    padLength += maxPlainTextSize - inLength;
	}

	// pad
	ps = new byte[padLength];
	secureRandom.nextBytes(ps);

	// all bytes must be != 0x00
	// oops what, if the 255th padding byte = 0x00 ?
	for (int i = padLength; --i >= 0;) {
	    if (ps[i] == 0x00) {
		ps[i] = (byte) ((i % 254) + 1);
	    }
	}

	System.arraycopy(ps, 0, m, 2, padLength);
	m[padLength + 2] = 0x00;

	System.arraycopy(input, 0, m, padLength + 3, inLength);

	bigInt = new FlexiBigInt(1, m);

	try {
	    x = PKCS1Operations.RSAEP(pubKey, bigInt);
	    cBytes = PKCS1Operations.I2OSP(x, cipherTextSize);
	} catch (PKCS1Exception pkcs1ex) {
	    throw new BadPaddingException("PKCS1Exception: "
		    + pkcs1ex.getMessage());
	}

	return cBytes;
    }

    /**
     * Decrypt the ciphertext stored in <tt>input</tt>.
     * 
     * @param input
     *                the ciphertext
     * @return the plain text as byte array
     * @throws IllegalBlockSizeException
     *                 if the length of the input does not match the expected
     *                 length.
     * @throws BadPaddingException
     *                 if the decrypted header does not match the expected
     *                 header or a PKCS1Exception is thrown by the decryption
     *                 primitive.
     */
    protected byte[] messageDecrypt(byte[] input)
	    throws IllegalBlockSizeException, BadPaddingException {

	if (cipherTextSize != input.length) {
	    throw new IllegalBlockSizeException("RSA_PKCS1_v1_5 decryption "
		    + "error: the length of the input is not equal "
		    + "to the expected ciphertext length.");
	}

	if (cipherTextSize < HEADER_SIZE) {
	    throw new IllegalBlockSizeException("RSA_PKCS1_v1_5 decryption "
		    + "error: the length of the header is greater"
		    + "than the expected ciphertext length.");
	}

	// decrypt
	byte[] cBytes = new byte[cipherTextSize];
	System.arraycopy(input, 0, cBytes, 0, cipherTextSize);
	FlexiBigInt c = PKCS1Operations.OS2IP(cBytes);

	FlexiBigInt m = null;
	byte[] mBytes = null;
	try {
	    m = PKCS1Operations.RSADP(privKey, c);
	    mBytes = PKCS1Operations.I2OSP(m, cipherTextSize);
	} catch (PKCS1Exception pkcs1ex) {
	    throw new BadPaddingException("PKCS1Exception: "
		    + pkcs1ex.getMessage());
	}

	if (mBytes[1] != 0x02) {
	    throw new BadPaddingException("RSA_PKCS1_v1_5 decrpytion error: "
		    + "wrong blocktype (should be 0x02).");
	}

	int i = 2;
	for (; mBytes[i] != 0x00; i++)
	    // processing is done in loop statements
	    ;

	if (i < HEADER_SIZE - 1) {
	    throw new BadPaddingException("RSA_PKCS1_v1_5 decryption error: "
		    + "the header does not match the expected header.");
	}

	i++;
	int cSizeI = cipherTextSize - i;

	byte[] out = new byte[cSizeI];
	System.arraycopy(mBytes, i, out, 0, cSizeI);

	return out;
    }

}
