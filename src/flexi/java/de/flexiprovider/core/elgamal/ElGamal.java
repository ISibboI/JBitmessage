/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.elgamal;

import de.flexiprovider.api.AsymmetricBlockCipher;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.exceptions.BadPaddingException;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.keys.Key;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.util.FlexiBigIntUtils;

/**
 * This class implements ElGamal encryption. A ciphertext block consists of the
 * two numbers B = g<sup>b</sup>mod p and c = A<sup>b</sup> * m mod p (m =
 * message). For details about the parameters g, p and A see
 * {@link ElGamalKeyPairGenerator}.
 * <p>
 * To encrypt a message, the following steps have to be performed:
 * 
 * <pre>
 * // The message which should be encrypted
 * String message = &quot;secret message&quot;;
 * byte[] messageBytes = message.getBytes();
 * 
 * // The source of randomness
 * SecureRandom secureRandom = Registry.getSecureRandom();
 * 
 * // Obtain a ElGamal Cipher Object
 * Cipher elGamalCipher = Cipher.getInstance(&quot;ElGamal&quot;);
 * 
 * // Obtain the corresponding key pair generator
 * KeyPairGenerator elGamalKPG = KeyPairGenerator.getInstance(&quot;ElGamal&quot;);
 * 
 * // Initialize the key pair generator with the desired strength
 * elGamalKPG.initialize(1024);
 * 
 * // Generate a key pair
 * KeyPair elGamalKeyPair = elGamalKPG.genKeyPair();
 * 
 * // Initialize the cipher
 * cipher.init(Cipher.ENCRYPT_MODE, elGamalKeyPair.getPublic(), secureRandom);
 * 
 * // Finally encrypt the message
 * byte[] ciphertextBytes = cipher.doFinal(messageBytes);
 * </pre>
 * 
 * Decrypting a message is similar to encryption, except the <TT>Cipher</TT>
 * must be initialized with <TT>Cipher.DECRYPT_MODE</TT> and the private key (
 * <TT>elGamalKeyPair.getPrivate()</TT>).
 * <p>
 * 
 * On an AMD Athlon 550 MHz with a 1024 bit key the encryption rate is about 5
 * kB/sec, the decryption rate is about 17 kB/sec.
 * 
 * @author Thomas Wahrenbruch
 * @see ElGamalKeyPairGenerator
 * @see ElGamalPublicKey
 * @see ElGamalPrivateKey
 */
public class ElGamal extends AsymmetricBlockCipher {

	/**
	 * The algorithm name.
	 */
	public static final String ALG_NAME = "ElGamal";

	/**
	 * The OID of ElGamal.
	 */
	public static final String OID = ElGamalKeyFactory.OID;

	// the modulus p describing the group (Zp/Z)*
	private FlexiBigInt modulus;

	// a generator of the group (Zp/Z)*
	private FlexiBigInt generator;

	// the public value A = g<sup>a</sup> mod p
	private FlexiBigInt publicA;

	// the private a
	private FlexiBigInt secretA;

	// the source of randomness
	private SecureRandom secureRandom = null;

	/**
	 * Return the name of this cipher.
	 * 
	 * @return "ElGamal"
	 */
	public String getName() {
		return ALG_NAME;
	}

	/**
	 * Return the key size of the given key object in bits. Checks whether the
	 * key object is an instance of <tt>ElGamalPublicKey</tt> or
	 * <tt>ElGamalPrivateKey</tt>.
	 * 
	 * @param key
	 *            the key object
	 * @return the key size of the given key object.
	 * @throws InvalidKeyException
	 *             if key is invalid.
	 */
	public int getKeySize(Key key) throws InvalidKeyException {
		if (key instanceof ElGamalPrivateKey) {
			return ((ElGamalPrivateKey) key).getModulus().bitLength();
		}
		if (key instanceof ElGamalPublicKey) {
			return ((ElGamalPublicKey) key).getModulus().bitLength();
		}
		throw new InvalidKeyException("Unsupported key.");
	}

	/**
	 * Initialize the block cipher with a key for data encryption. Parameters
	 * are currently not supported.
	 * 
	 * @param key
	 *            the key which has to be used to encrypt data.
	 * @param params
	 *            the algorithm parameters.
	 * @param secureRandom
	 *            a source of randomness.
	 * @throws InvalidKeyException
	 *             if the given key is inappropriate for initializing this
	 *             cipher.
	 */
	protected void initCipherEncrypt(Key key, AlgorithmParameterSpec params,
			SecureRandom secureRandom) throws InvalidKeyException {

		if (!(key instanceof ElGamalPublicKey)) {
			throw new InvalidKeyException("key is not an ElGamalPublicKey");
		}

		ElGamalPublicKey pubKey = (ElGamalPublicKey) key;
		modulus = pubKey.getModulus();
		generator = pubKey.getGenerator();
		publicA = pubKey.getPublicA();
		this.secureRandom = secureRandom;

		maxPlainTextSize = ((modulus.bitLength() - 1) >> 3) - 1;
		if (maxPlainTextSize < 0) {
			throw new InvalidKeyException("Modulus bit length too small.");
		}
		cipherTextSize = ((modulus.bitLength() + 7) >> 3) << 1;
	}

	/**
	 * Initialize the block cipher with a key for data encryption. Parameters
	 * are currently not supported.
	 * 
	 * @param key
	 *            the key which has to be used to decrypt data.
	 * @param params
	 *            the algorithm parameters.
	 * @throws InvalidKeyException
	 *             if the given key is inappropriate for initializing this
	 *             cipher.
	 */
	protected void initCipherDecrypt(Key key, AlgorithmParameterSpec params)
			throws InvalidKeyException {

		if (!(key instanceof ElGamalPrivateKey)) {
			throw new InvalidKeyException("Key is not a ElGamal Private Key");
		}

		ElGamalPrivateKey privKey = (ElGamalPrivateKey) key;
		modulus = privKey.getModulus();
		generator = privKey.getGenerator();
		secretA = privKey.getA();

		maxPlainTextSize = ((modulus.bitLength() - 1) >> 3) - 1;
		cipherTextSize = ((modulus.bitLength() + 7) >> 3) << 1;
	}

	/**
	 * Encrypt a message.
	 * 
	 * @param input
	 *            the message
	 * @return the encrypted message
	 */
	protected byte[] messageEncrypt(byte[] input) {

		// pad the message and convert to FlexiBigInt
		FlexiBigInt pm = pad(input);

		// find a random b, 0 < b < modulus - 1
		FlexiBigInt pSubOne = modulus.subtract(FlexiBigInt.ONE);
		FlexiBigInt b;
		do {
			b = new FlexiBigInt(modulus.bitLength() - 1, secureRandom);
		} while ((b.compareTo(FlexiBigInt.ZERO) <= 0)
				|| (b.compareTo(pSubOne) >= 0));

		// encrypt
		FlexiBigInt bigB = generator.modPow(b, modulus);
		FlexiBigInt c = (pm.multiply(publicA.modPow(b, modulus))).mod(modulus);

		// write encrypted data into the output-array
		byte[] bigBBytes = FlexiBigIntUtils.toMinimalByteArray(bigB);
		byte[] cBytes = FlexiBigIntUtils.toMinimalByteArray(c);

		byte[] result = new byte[cipherTextSize];

		System.arraycopy(bigBBytes, 0, result, (cipherTextSize >> 1)
				- bigBBytes.length, bigBBytes.length);
		System.arraycopy(cBytes, 0, result, cipherTextSize - cBytes.length,
				cBytes.length);

		return result;
	}

	/**
	 * Pad a message.
	 * 
	 * @param mBytes
	 *            the message
	 * @return the padded message
	 */
	private FlexiBigInt pad(byte[] mBytes) {
		byte[] pmBytes = new byte[mBytes.length + 1];
		pmBytes[0] = 0x01;
		System.arraycopy(mBytes, 0, pmBytes, 1, mBytes.length);
		return new FlexiBigInt(1, pmBytes);
	}

	/**
	 * Decrypt a ciphertext.
	 * 
	 * @param input
	 *            the ciphertext
	 * @return the decrypted ciphertext
	 * @throws BadPaddingException
	 *             if the ciphertext is invalid.
	 */
	protected byte[] messageDecrypt(byte[] input) throws BadPaddingException {

		int cTextDiv2 = cipherTextSize >> 1;

		// extract bigB and the ciphertext
		byte[] bigBBytes = new byte[cTextDiv2];
		System.arraycopy(input, 0, bigBBytes, 0, cTextDiv2);
		FlexiBigInt bigB = new FlexiBigInt(1, bigBBytes);

		byte[] cBytes = new byte[cTextDiv2];
		System.arraycopy(input, cTextDiv2, cBytes, 0, cTextDiv2);

		FlexiBigInt c = new FlexiBigInt(1, cBytes);

		// decrypt message representative
		FlexiBigInt pm = c.multiply(bigB.modPow(secretA.negate(), modulus))
				.mod(modulus);

		// unpad and return plaintext
		return unpad(pm);
	}

	/**
	 * Unpad a message.
	 * 
	 * @param pm
	 *            the padded message
	 * @return the message
	 * @throws BadPaddingException
	 *             if the padded message is invalid.
	 */
	private byte[] unpad(FlexiBigInt pm) throws BadPaddingException {
		byte[] mrBytes = pm.toByteArray();
		if (mrBytes[0] != 0x01) {
			throw new BadPaddingException("invalid ciphertext");
		}
		byte[] mBytes = new byte[mrBytes.length - 1];
		System.arraycopy(mrBytes, 1, mBytes, 0, mBytes.length);
		return mBytes;
	}

}
