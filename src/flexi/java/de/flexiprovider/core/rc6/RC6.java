/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.rc6;

import de.flexiprovider.api.BlockCipher;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.keys.Key;
import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.api.keys.SecretKeySpec;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.util.LittleEndianConversions;

/**
 * RC6BlockCipher implements the RC6 Cipher. It uses a block size of 16 Bytes, a
 * wordlength of 32 bits and uses 20 rounds when encrypting/decrypring. These
 * value conform to the AES standards. RC6 keys of any length should work.
 * Default values for key size are 8, 16 and 24 bytes.
 * 
 * @author Christoph Sesterhenn, Christoph Ender
 * @author Oliver Seiler
 */
public class RC6 extends BlockCipher {

	/**
	 * The algorithm name.
	 */
	public static final String ALG_NAME = "RC6";

	private int[] S;

	private static final int blockSize = 16;

	private static final int rounds = 20;

	private static final int P32 = (int) 3084996963L;

	private static final int Q32 = (int) 2654435769L;

	/**
	 * @return the name of this cipher
	 */
	public String getName() {
		return ALG_NAME;
	}

	/**
	 * Returns the key size of the given key object. Checks whether the key
	 * object is an instance of <tt>RC6Key</tt> or <tt>SecretKeySpec</tt>.
	 * 
	 * @param key
	 *            the key object
	 * @return the key size of the given key object.
	 * @throws InvalidKeyException
	 *             if key is invalid.
	 */
	public int getKeySize(Key key) throws InvalidKeyException {
		if ((!(key instanceof RC6Key)) && (!(key instanceof SecretKeySpec))) {
			throw new InvalidKeyException("Not a RC6 Key");
		}

		int keyLen = key.getEncoded().length;

		keyLen -= keyLen & 3;

		return keyLen << 3;
	}

	/**
	 * This method returns the blocksize, the algorithm uses. This method will
	 * normaly be called by the padding scheme. It must be asured, that this
	 * method is exclusivly called, when the algorithm is either in encryption
	 * or in decryption mode.
	 * 
	 * @return the used blocksize
	 */
	public int getCipherBlockSize() {
		return blockSize;
	}

	/**
	 * This method guarantees the AlgorithmParameterSpec compatibility. As these
	 * are not used here it just calls the origin InitDecrypt method.
	 * 
	 * @param key
	 *            - the SecretKey which has to be used to decrypt data.
	 * @param params
	 *            - algorithmParameterSpec, not used for here
	 * @throws InvalidKeyException
	 *             if the given key is inappropriate for initialising this
	 *             cipher.
	 */
	protected void initCipherEncrypt(SecretKey key,
			AlgorithmParameterSpec params) throws InvalidKeyException {
		if (!(key instanceof RC6Key)) {
			throw new InvalidKeyException("not a RC6 Key");
		}
		keySchedule(key.getEncoded());
	}

	/**
	 * This method guarantees the AlgorithmParameterSpec compatibility. As these
	 * are not used here it just calls the origin InitEncrypt method.
	 * 
	 * @param key
	 *            - the SecretKey which has to be used to decrypt data.
	 * @param params
	 *            - algorithmParameterSpec, not used for here
	 * @throws InvalidKeyException
	 *             if the given key is inappropriate for initialising this
	 *             cipher.
	 */
	protected void initCipherDecrypt(SecretKey key,
			AlgorithmParameterSpec params) throws InvalidKeyException {
		initCipherEncrypt(key, params);
	}

	/**
	 * This method implements the RC6 Key schedule.
	 * 
	 * @param key
	 *            An array of bytes contaning the data for the key.
	 */
	private void keySchedule(byte[] key) {

		int c = ((key.length << 3) + 31) >> 5;
		int[] L = new int[c];

		for (int i = 0; i < (key.length >> 2); i++) {
			for (int j = 0; j < 4; j++) {
				int swp = (key[(i << 2) + j]) & 0xff;
				L[i] += swp << (j << 3);
			}
		}

		S = new int[(rounds << 1) + 4];

		S[0] = P32;

		for (int i = 1; i <= (rounds << 1) + 3; i++) {
			S[i] = S[i - 1] + Q32;
		}

		int A = 0;
		int B = 0;
		int i = 0;
		int j = 0;

		int v = 3 * Math.max(c, (rounds << 1) + 4);
		for (int s = 1; s <= v; s++) {
			S[i] = leftRotate(S[i] + A + B, 3);
			A = S[i];
			L[j] = leftRotate(L[j] + A + B, (A + B) & 0x1f);
			B = L[j];
			i = (i + 1) % ((rounds << 1) + 4);
			j = (j + 1) % c;
		}
	}

	/**
	 * This method encrypts a single block of data, and may only be called, when
	 * the block cipher is in encrytion mode. It has to be asured, too, that the
	 * array <TT>in</TT> contains a whole block starting at <TT>inOffset</TT>
	 * and that <TT>out</TT> is large enogh to hold an encrypted block starting
	 * at <TT>outOffset</TT>
	 * 
	 * @param input
	 *            array of bytes which contains the plaintext to be encrypted
	 * @param inOff
	 *            index in array in, where the plaintext block starts
	 * @param output
	 *            array of bytes which will contain the ciphertext startig at
	 *            outOffset
	 * @param outOff
	 *            index in array out, where the ciphertext block will start
	 */
	protected void singleBlockEncrypt(byte[] input, int inOff, byte[] output,
			int outOff) {

		int A = LittleEndianConversions.OS2IP(input, inOff);
		int B = LittleEndianConversions.OS2IP(input, inOff + 4);
		int C = LittleEndianConversions.OS2IP(input, inOff + 8);
		int D = LittleEndianConversions.OS2IP(input, inOff + 12);

		B += S[0];
		D += S[1];

		for (int i = 1; i <= rounds; i++) {
			int t = (B << 1) + 1;
			t *= B;
			t = leftRotateBy5(t);

			int u = (D << 1) + 1;
			u *= D;
			u = leftRotateBy5(u);

			A = leftRotate(A ^ t, u & 31) + S[i << 1];

			C = leftRotate(C ^ u, t & 31) + S[(i << 1) + 1];

			int swp = A;
			A = B;
			B = C;
			C = D;
			D = swp;
		}

		A += S[(rounds << 1) + 2];
		C += S[(rounds << 1) + 3];

		LittleEndianConversions.I2OSP(A, output, outOff);
		LittleEndianConversions.I2OSP(B, output, outOff + 4);
		LittleEndianConversions.I2OSP(C, output, outOff + 8);
		LittleEndianConversions.I2OSP(D, output, outOff + 12);
	}

	/**
	 * This method decrypts a single block of data, and may only be called, when
	 * the block cipher is in decrytion mode. It has to be asured, too, that the
	 * array <TT>in</TT> contains a whole block starting at <TT>inOffset</TT>
	 * and that <TT>out</TT> is large enogh to hold an decrypted block starting
	 * at <TT>outOffset</TT>
	 * 
	 * @param input
	 *            array of bytes which contains the ciphertext to be decrypted
	 * @param inOff
	 *            index in array in, where the ciphertext block starts
	 * @param output
	 *            array of bytes which will contain the plaintext starting at
	 *            outOffset
	 * @param outOff
	 *            index in array out, where the plaintext block will start
	 */
	protected void singleBlockDecrypt(byte[] input, int inOff, byte[] output,
			int outOff) {

		int A = LittleEndianConversions.OS2IP(input, inOff);
		int B = LittleEndianConversions.OS2IP(input, inOff + 4);
		int C = LittleEndianConversions.OS2IP(input, inOff + 8);
		int D = LittleEndianConversions.OS2IP(input, inOff + 12);

		C -= S[(rounds << 1) + 3];
		A -= S[(rounds << 1) + 2];

		for (int i = rounds; i >= 1; i--) {
			int swp = A;
			A = D;
			D = C;
			C = B;
			B = swp;

			int u = (D << 1) + 1;
			u *= D;
			u = leftRotateBy5(u);

			int t = (B << 1) + 1;
			t *= B;
			t = leftRotateBy5(t);

			C -= S[(i << 1) + 1];
			C = rightRotate(C, t & 31) ^ u;

			A -= S[i << 1];
			A = rightRotate(A, u & 31) ^ t;
		}

		D -= S[1];
		B -= S[0];

		LittleEndianConversions.I2OSP(A, output, outOff);
		LittleEndianConversions.I2OSP(B, output, outOff + 4);
		LittleEndianConversions.I2OSP(C, output, outOff + 8);
		LittleEndianConversions.I2OSP(D, output, outOff + 12);
	}

	private static int rightRotate(int data, int n) {
		return (data >>> n) | (data << (32 - n));
	}

	private static int leftRotate(int data, int n) {
		return (data << n) | (data >>> (32 - n));
	}

	private static int leftRotateBy5(int data) {
		return (data << 5) | (data >>> 27);
	}

}
