/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.elgamal.semanticallysecure;

import de.flexiprovider.api.AsymmetricBlockCipher;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.exceptions.BadPaddingException;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.keys.Key;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.util.FlexiBigIntUtils;

/**
 * This class implements a semantically secure variant of the original ElGamal
 * encryption. The implementation is based on algorithm 14.2, page 476 of the
 * book: Modern Cryptography - Theory & Practice by Wenbo Mao.
 * 
 * @author Thomas Wahrenbruch
 * @author Roberto Samarone dos Santos Araújo
 * 
 */
public class SSVElGamal extends AsymmetricBlockCipher {

	/**
	 * The algorithm name.
	 */
	public static final String ALG_NAME = "SSVElGamal";

	/* The modulus p describing the group (Zp/Z)* */
	private FlexiBigInt modulusP;

	/* the modulus q describing the subgroup (Zq/Zp)* */
	private FlexiBigInt modulusQ;

	/* a generator of the group (Zp/Z)* */
	private FlexiBigInt generator;

	/* the public value A = g<sup>a</sup> mod p */
	private FlexiBigInt publicA;

	/* the private a */
	private FlexiBigInt secretA;

	/* the source of randomness */
	private SecureRandom secureRandom = null;

	/**
	 * Return the name of this cipher.
	 * 
	 * @return {@link ALG_NAME}
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
		if (key instanceof SSVElGamalPrivateKey) {
			return ((SSVElGamalPrivateKey) key).getModulusQ().bitLength();
		}
		if (key instanceof SSVElGamalPublicKey) {
			return ((SSVElGamalPublicKey) key).getModulusP().bitLength();
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

		if (!(key instanceof SSVElGamalPublicKey)) {
			throw new InvalidKeyException("key is not an SSVElGamalPublicKey");
		}

		SSVElGamalPublicKey pubKey = (SSVElGamalPublicKey) key;
		modulusP = pubKey.getModulusP();

		modulusQ = pubKey.getModulusQ();

		generator = pubKey.getGenerator();
		publicA = pubKey.getPublicA();
		this.secureRandom = secureRandom;

		maxPlainTextSize = ((modulusQ.bitLength() - 1) >> 3) - 1;
		if (maxPlainTextSize < 0) {
			throw new InvalidKeyException("Modulus bit length too small.");
		}
		cipherTextSize = ((modulusP.bitLength() + 7) >> 3) << 1;
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

		if (!(key instanceof SSVElGamalPrivateKey)) {
			throw new InvalidKeyException(
					"Key is not an SSVElGamal Private Key");
		}

		SSVElGamalPrivateKey privKey = (SSVElGamalPrivateKey) key;
		modulusP = privKey.getModulusP();
		modulusQ = privKey.getModulusQ();
		generator = privKey.getGenerator();
		secretA = privKey.getA();

		maxPlainTextSize = ((modulusQ.bitLength() - 1) >> 3) - 1;
		cipherTextSize = ((modulusP.bitLength() + 7) >> 3) << 1;
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

		// encode the padded message to an element in the subgroup Zq
		pm = pm2sg(pm);

		// find a random b, 0 < b < modulusq - 1
		FlexiBigInt pSubOne = modulusQ.subtract(FlexiBigInt.ONE);
		FlexiBigInt b;
		do {
			b = new FlexiBigInt(modulusQ.bitLength() - 1, secureRandom);
		} while ((b.compareTo(FlexiBigInt.ZERO) <= 0)
				|| (b.compareTo(pSubOne) >= 0));

		// encrypt
		FlexiBigInt bigB = generator.modPow(b, modulusP);
		FlexiBigInt c = (pm.multiply(publicA.modPow(b, modulusP)))
				.mod(modulusP);

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
	 * Encode a padded message to an element of the subgroup
	 * 
	 * @param pm
	 *            the padded message
	 * 
	 * @return an element from the subgroup Zq
	 * 
	 */
	private FlexiBigInt pm2sg(FlexiBigInt pm) {

		FlexiBigInt msgTemp = pm.add(FlexiBigInt.ONE);

		if ((msgTemp.modPow(modulusQ, modulusP)).equals(FlexiBigInt.ONE)) {
			return msgTemp;
		}
		return modulusP.subtract(msgTemp);
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
		FlexiBigInt pm = c.multiply(bigB.modPow(secretA.negate(), modulusP))
				.mod(modulusP);

		// Decode an element in the subgroup Zq to a padded message
		pm = sg2pm(pm);

		// unpad and return plaintext
		return unpad(pm);
	}

	/**
	 * Decode the element of the subgroup to the padded message
	 * 
	 * @param sgElement
	 *            an element from the subgroup Zq
	 * 
	 * @return the padded message
	 * 
	 */
	private FlexiBigInt sg2pm(FlexiBigInt sgElement) {

		if (sgElement.compareTo(modulusQ) < 0
				|| sgElement.compareTo(modulusQ) == 0) {
			return sgElement.subtract(FlexiBigInt.ONE);

		}
		return (modulusP.subtract(sgElement)).subtract(FlexiBigInt.ONE);
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
