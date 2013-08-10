/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.rsa;

import java.io.IOException;

import de.flexiprovider.api.AsymmetricBlockCipher;
import de.flexiprovider.api.MessageDigest;
import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.exceptions.InvalidParameterException;
import de.flexiprovider.api.exceptions.InvalidParameterSpecException;
import de.flexiprovider.api.exceptions.NoSuchAlgorithmException;
import de.flexiprovider.api.keys.Key;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.api.parameters.AlgorithmParameters;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.core.rsa.interfaces.RSAPrivateCrtKey;
import de.flexiprovider.core.rsa.interfaces.RSAPrivateKey;
import de.flexiprovider.core.rsa.interfaces.RSAPublicKey;

/**
 * This class implements the RSA algorithm as defined in <a
 * href=http://www.rsasecurity.com/rsalabs/node.asp?id=2125>PKCS#1 version 2.1</a>
 * in the OAEP (Optimal Asymmetric Encryption Padding) mode. The OAEP mode is
 * recommended for new applications.
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
 * // Obtain a RSA Cipher Object
 * Cipher rsaCipher = Cipher.getInstance(&quot;RSA_PKCS1_v2_1&quot;);
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
 * 2. If some of the PKCS1 functions fail during encryption, a RuntimeException
 * is thrown.
 * 
 * @author Thomas Wahrenbruch
 * @author Ralf-Philipp Weinmann
 */
public class RSA_PKCS1_v2_1 extends AsymmetricBlockCipher {

    /**
     * The OID of RSA_PKCS1_v2_1.
     */
    public static final String OID = "1.2.840.113549.1.1.7";

    // source of randomness
    private SecureRandom sr;

    // the public key
    private RSAPublicKey pubKey;

    // the private key
    private RSAPrivateKey privKey;

    // the message digest algorithm
    private MessageDigest md;

    /**
     * @return the name of this cipher
     */
    public String getName() {
	return "RSA_PKCS1_v2_1";
    }

    /**
     * Returns the key size of the given key object. Checks whether the key
     * object is an instance of <tt>RSAPublicKey</tt> or
     * <tt>RSAPrivateKey</tt>. Would be simpler to just check for
     * <tt>RSAKey</tt> but this breaks build with Java 1.2.
     * 
     * @param key
     *                the key object
     * @return the key size of the given key object.
     * @throws InvalidKeyException
     *                 if key is invalid.
     */
    public int getKeySize(Key key) throws InvalidKeyException {
	if (key instanceof RSAPrivateKey) {
	    return ((RSAPrivateKey) key).getN().bitLength();
	} else if (key instanceof RSAPublicKey) {
	    return ((RSAPublicKey) key).getN().bitLength();
	} else {
	    throw new InvalidKeyException("RSA_PKCS1_v2_1: engineGetKeySize()"
		    + " - the key is not suitable for RSA the algorithm!");
	}
    }

    /**
     * This method initializes the block cipher with a certain key and
     * parameters for data encryption.
     * 
     * @param key
     *                the key which has to be used to encrypt data
     * @param params
     *                the algorithm parameters
     * @param secureRandom
     *                the source of randomness
     * @throws InvalidKeyException
     *                 if the given key is inappropriate for initializing this
     *                 cipher.
     */
    protected void initCipherEncrypt(Key key, AlgorithmParameterSpec params,
	    SecureRandom secureRandom) throws InvalidKeyException {

	if (!(key instanceof RSAPublicKey)) {
	    throw new InvalidKeyException("RSA_PKCS1_v2_1: initEncrypt - "
		    + "RSASSA-OAEP needs an RSAPublicKey for encrypting data.");
	}

	if (params == null) {
	    initParams(new RSAOAEPParameterSpec());
	} else if (params instanceof RSAOAEPParameterSpec) {
	    initParams((RSAOAEPParameterSpec) params);
	} else {
	    throw new InvalidParameterException("RSA_PKCS1_v2_1: initEncrypt"
		    + " - Invalid parameter specifaction!");
	}

	pubKey = (RSAPublicKey) key;
	privKey = null;
	sr = secureRandom;

	cipherTextSize = ((pubKey.getN().bitLength()) + 7) >> 3;
	maxPlainTextSize = cipherTextSize - (md.getDigestLength() << 1) - 2;

	if (maxPlainTextSize <= 0) {
	    throw new InvalidParameterException(
		    "RSA_PKCS1_v2_1: initEncrypt - Please use larger modulus!");
	}
    }

    /**
     * This method initializes the block cipher with a certain key and
     * parameters for data encryption.
     * 
     * @param key
     *                the key which has to be used to decrypt data
     * @param params
     *                the algorithm parameters
     * @throws InvalidKeyException
     *                 if the given key is inappropriate for initializing this
     *                 cipher.
     */
    protected void initCipherDecrypt(Key key, AlgorithmParameterSpec params)
	    throws InvalidKeyException {

	if (params == null) {
	    initParams(new RSAOAEPParameterSpec());
	} else if (params instanceof RSAOAEPParameterSpec) {
	    initParams((RSAOAEPParameterSpec) params);
	} else {
	    throw new InvalidParameterException("RSA_PKCS1_v2_1: initDecrypt"
		    + " - Invalid parameter specifaction!");
	}

	if (key instanceof RSAPrivateCrtKey || key instanceof RSAPrivateKey) {
	    privKey = (RSAPrivateKey) key;
	    pubKey = null;
	    sr = Registry.getSecureRandom();

	    cipherTextSize = ((privKey.getN().bitLength()) + 7) >> 3;
	    maxPlainTextSize = cipherTextSize - (md.getDigestLength() << 1) - 2;
	} else {
	    throw new InvalidKeyException("RSA_PKCS1_v2_1: initDecrypt - "
		    + "RSASSA-OAEP needs a RSAPublicKey for encrypting data.");
	}

	if (maxPlainTextSize <= 0) {
	    throw new InvalidParameterException(
		    "RSA_PKCS1_v2_1: initDecrypt - Please use larger modulus!");
	}
    }

    private void initParams(RSAOAEPParameterSpec paramSpec) {
	String mdOID = paramSpec.getMD();
	byte[] paramBytes;
	try {
	    md = Registry.getMessageDigest(mdOID);
	    AlgorithmParameters params = new RSAOAEPParameters();
	    params.init(paramSpec);
	    paramBytes = params.getEncoded();
	} catch (NoSuchAlgorithmException e) {
	    throw new RuntimeException("did not find message digest '" + mdOID
		    + "'");
	} catch (InvalidParameterSpecException e) {
	    // unexpected: the parameter spec is of the right type
	    throw new RuntimeException("internal error");
	} catch (IOException e) {
	    // unexpected: the parameter spec is well-formed
	    throw new RuntimeException("internal error");
	}

	md.update(paramBytes);
    }

    /**
     * Encrypt a message.
     * 
     * @param input
     *                the plaintext
     * @return the encrypted plaintext
     */
    protected byte[] messageEncrypt(byte[] input) {

	// 1. Length checking:
	// a. If the length of L is greater than the input limitation for the
	// hash function (261 – 1 octets for SHA-1), output “label too long” and
	// stop.

	// b. If mLen > k – 2hLen – 2, output “message too long” and stop.
	// if (input.length > maxPlainTextSize_) {
	// new RuntimeException("RSA_PKCS1_v2_1: messageEncrypt "
	// + "- decryption error");
	// }

	byte[] C = null;
	byte[] EM = null;
	byte[] M = input;
	FlexiBigInt c = null;
	FlexiBigInt m = null;

	try {
	    // 2) EME-OAEP encoding of message.
	    EM = PKCS1Operations.EME_OAEP_ENCODE(M, null, cipherTextSize, md,
		    sr);

	    // 3) RSA encryption:
	    // a) Convert the encoded message EM to an integer message
	    // representative m
	    m = PKCS1Operations.OS2IP(EM);

	    // b) Apply the RSAEP encryption primitive to the RSA public key (n,
	    // e) and the
	    // message representative m to produce an integer ciphertext
	    // representative c
	    c = PKCS1Operations.RSAEP(pubKey, m);

	    // c) Convert the ciphertext representative c to a ciphertext C of
	    // length k octets:
	    // C = I2OSP (c, k)
	    C = PKCS1Operations.I2OSP(c, cipherTextSize);
	} catch (PKCS1Exception pkcs1e) {
	    throw new RuntimeException(
		    "RSA_PKCS1_v2_1: messageEncrypt"
			    + "Internal error occured during PKCS#1 / RSASSA-OAEP encryption.");
	}

	// 4) Output the ciphertext C.
	// System.arraycopy(C, 0, out, outOffset, C.length);
	return C;
    }

    /**
     * Decrypt a ciphertext.
     * 
     * @param input
     *                the ciphertext
     * @return the decrypted ciphertext
     */
    protected byte[] messageDecrypt(byte[] input) {
	// 1. Length checking:
	// a. If the length of L is greater than the input limitation for the
	// hash function
	// (261 – 1 octets for SHA-1), output “decryption error” and stop.

	// b. If the length of the ciphertext C is not k octets, output
	// “decryption error”
	// and stop.
	if (input.length != cipherTextSize) {
	    throw new RuntimeException("RSA_PKCS1_v2_1: messageDecrypt "
		    + "- decryption error");
	}

	// c. If k < 2hLen + 2, output “decryption error” and stop.
	if (cipherTextSize < (md.getDigestLength() << 1) + 2) {
	    new RuntimeException("RSA_PKCS1_v2_1: messageDecrypt "
		    + "- decryption error");
	}

	byte[] EM = null;
	byte[] M = null;
	FlexiBigInt c = PKCS1Operations.OS2IP(input);
	FlexiBigInt m = null;

	try {
	    m = PKCS1Operations.RSADP(privKey, c);
	    EM = PKCS1Operations.I2OSP(m, cipherTextSize);
	    M = PKCS1Operations.EME_OAEP_DECODE(EM, null, cipherTextSize, md);
	} catch (PKCS1Exception ex) {
	    throw new RuntimeException("RSA_PKCS1_v2_1: PKCS1Exception - "
		    + ex.getMessage());
	}

	return M;
    }

}
