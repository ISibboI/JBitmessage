/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.rc5;

import de.flexiprovider.api.BlockCipher;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.keys.Key;
import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.api.keys.SecretKeySpec;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;

/**
 * This class implements the RC5 block-cipher algorithm according to the RFC
 * 2040. RC5 was invented by Ronald Rivest for RSA Security in 1994. Further
 * information can be found at <a href="www.rsasecurity.com">RSA Security</a>,
 * in RFC 2040 and in the Handbook of Applied Cryptography, Menezes, van
 * Oorschot, Vanstone, CRC Press, 1997, algorithm 7.115, 7.116 and 7.117.
 * <p>
 * The efficiency of this implementation has been tested on a AMD K6-III, 450
 * MHz, running Windows 2000 Prof., using jdk 1.2.2. The encryption/decryption
 * rate is about 8.9 MBits / second using wordSize 32, rounds 12, keySize 16.
 * 
 * @author Oliver Seiler
 */
public class RC5 extends BlockCipher {

	/**
	 * The algorithm name.
	 */
	public static final String ALG_NAME = "RC5";

	// the word size in bits
	private int wordSize;

	// the word size in bytes
	private int wordSizeInBytes;

	private int numRounds = 0;

	// the key size in bytes
	private int keySize;

	// used for modulo 2^wordSize calculations
	private long moduloMask;

	private long P;

	private long Q;

	private long[] roundKey;

	// P and Q constants
	private static final long P16 = 0xb7e1;
	private static final long Q16 = 0x9e37;

	private static final long P32 = 0xb7e15163;
	private static final long Q32 = 0x9e3779b9;

	private static final long P64 = 0xb7e151628aed2a6bL;
	private static final long Q64 = 0x9e3779b97f4a7c15L;

	/**
	 * @return the name of this cipher
	 */
	public String getName() {
		return ALG_NAME;
	}

	/**
	 * Returns the key size of the given key object. Checks whether the key
	 * object is an instance of <tt>RC5Key</tt> or <tt>SecretKeySpec</tt>.
	 * 
	 * @param key
	 *            the key object
	 * @return the key size of the given key object.
	 * @throws InvalidKeyException
	 *             if key is invalid.
	 */
	public int getKeySize(Key key) throws InvalidKeyException {
		if ((!(key instanceof RC5Key)) && (!(key instanceof SecretKeySpec))) {
			throw new InvalidKeyException("Not a RC5 Key");
		}

		return key.getEncoded().length << 3;
	}

	/**
	 * This method returns the block size, the algorithm uses. This method will
	 * usually be called by the padding scheme. Be sure not to call this before
	 * initializing the cipher.
	 * 
	 * @return used block size in bytes
	 * @throws IllegalStateException
	 *             if called before initializing the cipher.
	 */
	public int getCipherBlockSize() throws IllegalStateException {
		return wordSizeInBytes << 1;
	}

	/**
	 * Initialize the block cipher with the given key for data encryption.
	 * 
	 * @param key
	 *            SecretKey to be used to encrypt data
	 * @param params
	 *            AlgorithmParamterSpec to be used with this algorithm
	 * @throws InvalidKeyException
	 *             if the given key is illegal for this cipher.
	 * @throws InvalidAlgorithmParameterException
	 *             if the given AlgorithmParameters are not appropriate for this
	 *             cipher.
	 */
	protected void initCipherEncrypt(SecretKey key,
			AlgorithmParameterSpec params) throws InvalidKeyException,
			InvalidAlgorithmParameterException {

		if (!(key instanceof RC5Key)) {
			throw new InvalidKeyException("unsupported type");
		}

		if (params == null) {
			// use the default parameters
			extractParameters(new RC5ParameterSpec());
		} else {
			if (!(params instanceof RC5ParameterSpec)) {
				throw new InvalidAlgorithmParameterException("unsupported type");
			}
			extractParameters((RC5ParameterSpec) params);
		}

		byte[] encodedKey = key.getEncoded();
		keySize = encodedKey.length;
		keySchedule(encodedKey);
	}

	/**
	 * Initialize the block cipher the given key for data decryption.
	 * 
	 * @param key
	 *            SecretKey to be used to decrypt data
	 * @param params
	 *            AlgorithmParamterSpec to be used with this algorithm
	 * @throws InvalidKeyException
	 *             if the given key is illegal for this cipher
	 * @throws InvalidAlgorithmParameterException
	 *             if the given AlgorithmParameters are not appropriate for this
	 *             cipher
	 */
	protected void initCipherDecrypt(SecretKey key,
			AlgorithmParameterSpec params) throws InvalidKeyException,
			InvalidAlgorithmParameterException {
		initCipherEncrypt(key, params);
	}

	/**
	 * shedule the RC5 key uses "& moduloMask" instead of "mod 2 ^ w"
	 */
	private void keySchedule(byte[] key) {
		int u = wordSizeInBytes;
		int c = (int) Math.ceil(((double) keySize) / ((double) u));
		long[] L = new long[c];
		int i, j;
		long A, B;
		int t;
		int s;

		roundKey = new long[Math.max((numRounds << 1) + 2, 4)];
		roundKey[0] = P;

		for (j = keySize; j <= c * u - 1; j++) {
			roundKey[j] = 0x00;
		}

		for (i = 0; i <= c - 1; i++) {
			L[i] = 0;
			for (j = 0; j <= u - 1; j++) {
				if ((i * u + j) < keySize) {
					L[i] += ((long) key[i * u + j] & 0xff) << (8 * j);
				}
			}
		}

		for (i = 1; i <= (numRounds << 1) + 1; i++) {
			roundKey[i] = (roundKey[i - 1] + Q) & moduloMask; // mod 2^w
		}

		i = 0;
		j = 0;
		A = 0;
		B = 0;
		t = Math.max(c, (numRounds << 1) + 2);
		for (s = 1; s <= 3 * t; s++) {
			roundKey[i] = rotateLeft((roundKey[i] + A + B) & moduloMask/*
																		 * mod 2
																		 * ^ w
																		 */, 3);
			A = roundKey[i];
			i = (i + 1) % ((numRounds << 1) + 2);
			L[j] = rotateLeft((L[j] + A + B) & moduloMask /* mod 2 ^ w */,
					(A + B) & moduloMask/* mod 2 ^ w */);
			B = L[j];
			j = (j + 1) % c;
		}
		u = 0;
		c = 0;
		L = null;
		A = 0;
		B = 0;
		t = 0;
		s = 0;
	}

	/**
	 * This method encrypts a single block of data, and may only be called, when
	 * the block cipher is in encrytion mode. It has to be asured, too, that the
	 * array <TT>in</TT> contains a whole block starting at <TT>inOffset</TT>
	 * and that <TT>out</TT> is large enogh to hold an encrypted block starting
	 * at <TT>outOffset</TT>
	 * 
	 * @param in
	 *            byte[] containing the plaintext to be encrypted starting at
	 *            inOffset
	 * @param inOffset
	 *            int index in the array in where the plaintext block starts
	 * @param out
	 *            byte[] which will contain the ciphertext startig at outOffset
	 * @param outOffset
	 *            int index in the array out where the ciphertext block will
	 *            start
	 */
	protected void singleBlockEncrypt(byte[] in, int inOffset, byte[] out,
			int outOffset) {
		// uses "& moduloMask" instead of "mod 2 ^ w" for speedup
		long A, B;
		int i;

		A = bytesToLong(in, inOffset, wordSizeInBytes);
		B = bytesToLong(in, inOffset + wordSizeInBytes, wordSizeInBytes);

		A = (A + roundKey[0]) & moduloMask; // mod 2^w
		B = (B + roundKey[1]) & moduloMask; // mod 2^w

		for (i = 1; i <= numRounds; i++) {
			A = (rotateLeft(A ^ B, B) + roundKey[i << 1]) & moduloMask; // mod
			// 2^w
			B = (rotateLeft(A ^ B, A) + roundKey[(i << 1) + 1]) & moduloMask; // mod
			// 2^w
		}

		longToBytes(out, outOffset, A, wordSizeInBytes);
		longToBytes(out, outOffset + wordSizeInBytes, B, wordSizeInBytes);
	}

	/**
	 * This method decrypts a single block of data, and may only be called, when
	 * the block cipher is in decrytion mode. It has to be asured, too, that the
	 * array <TT>in</TT> contains a whole block starting at <TT>inOffset</TT>
	 * and that <TT>out</TT> is large enogh to hold an decrypted block starting
	 * at <TT>outOffset</TT>
	 * 
	 * @param in
	 *            byte[] containing the ciphertext to be decrypted starting at
	 *            inOffset
	 * @param inOffset
	 *            int index in the array in where the ciphertext block starts
	 * @param out
	 *            byte[] which will contain the plaintext startig at outOffset
	 * @param outOffset
	 *            int index in the array out where the plaintext block will
	 *            start
	 */
	protected void singleBlockDecrypt(byte[] in, int inOffset, byte[] out,
			int outOffset) {
		// uses "& moduloMask" instead of "mod 2 ^ w" for speedup
		long A, B;
		int i;

		A = bytesToLong(in, inOffset, wordSizeInBytes);
		B = bytesToLong(in, inOffset + wordSizeInBytes, wordSizeInBytes);

		for (i = numRounds; i >= 1; i--) {

			B = rotateRight(
					(B - roundKey[(i << 1) + 1]) & moduloMask /* mod 2^w */, A)
					^ A;
			A = rotateRight((A - roundKey[i << 1]) & moduloMask /* mod 2^w */,
					B)
					^ B;
		}

		A = (A - roundKey[0]) & moduloMask; // mod 2^w
		B = (B - roundKey[1]) & moduloMask; // mod 2^w

		longToBytes(out, outOffset, A, wordSizeInBytes);
		longToBytes(out, outOffset + wordSizeInBytes, B, wordSizeInBytes);
	}

	/**
	 * Extract the given algorithm parameters and initialize wordSize,
	 * wordSizeInBytes, numRounds, moduloMask, P, and Q.
	 */
	private void extractParameters(RC5ParameterSpec params) {
		numRounds = params.getNumRounds();
		wordSize = params.getWordSize();

		switch (wordSize) {
		case 16:
			P = P16;
			Q = Q16;
			break;
		case 32:
			P = P32;
			Q = Q32;
			break;
		case 64:
			P = P64;
			Q = Q64;
			break;
		default:
			// parameters are checked by RC5ParameterSpec, so there is nothing
			// left to do
		}

		wordSizeInBytes = wordSize >> 3;
		moduloMask = 0xffffffffffffffffL >>> (64 - wordSize);
	}

	/**
	 * rotates left the given x by n digits using wordSize bits
	 */
	private long rotateLeft(long x, long n) {
		// use bit mask instead of word size !!!
		n %= wordSize;
		return ((x << n) | (x >>> (wordSize - n))) & moduloMask;
	}

	/**
	 * rotates right the given x by n digits using wordSize bits
	 */
	private long rotateRight(long x, long n) {
		n %= wordSize;
		return ((x >>> n) | (x << (wordSize - n))) & moduloMask;
	}

	/**
	 * converts a 8-byte long value into a byte array beginning at offset using
	 * little-endian
	 * 
	 * @param bytes
	 *            the byte array to hold the result
	 * @param offset
	 *            the integer offset into the byte array
	 * @param value
	 *            the long to convert
	 * @param numberOfBytes
	 *            the number of Bytes to convert within the long value
	 */
	private void longToBytes(byte[] bytes, int offset, long value,
			int numberOfBytes) {
		int i;
		for (i = 0; i < numberOfBytes; i++) {
			bytes[offset + i] = (byte) ((value >>> (i << 3)) & 0xff);
		}
	}

	/**
	 * converts a byte array beginning at offset into a 8-byte long value using
	 * little-endian
	 * 
	 * @param bytes
	 *            the byte array
	 * @param offset
	 *            the integer offset into the byte array
	 * @result long the resulting long
	 */
	private long bytesToLong(byte[] bytes, int offset, int numberOfBytes) {
		int i;
		long value = 0x0000000000000000;
		for (i = 0; i < numberOfBytes; i++) {
			value |= ((((long) bytes[offset + i]) /* & 4294967295L */) & 0xff) << (i << 3);
		}
		return value;
	}
}
