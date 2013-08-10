/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.shacal;

import de.flexiprovider.api.BlockCipher;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.keys.Key;
import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.api.keys.SecretKeySpec;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.util.BigEndianConversions;

/**
 * ShacalBlockCipher implements the SHACAL Cipher. It uses a block size of 160
 * (20 Bytes), a 128-512 bit key and uses 80 rounds for encryption/decryption.
 * 
 * @author Paul Nguentcheu
 */
public class Shacal extends BlockCipher {

	/**
	 * The algorithm name.
	 */
	public static final String ALG_NAME = "Shacal";

	// Constants
	private static final int k1 = 0x5a827999;
	private static final int k2 = 0x6ed9eba1;
	private static final int k3 = 0x8f1bbcdc;
	private static final int k4 = 0xca62c1d6;
	// 20 bytes = 160 bits
	private static final int BLOCK_SIZE = 20;
	private int[] w = new int[80];

	/**
	 * @return the name of this cipher
	 */
	public String getName() {
		return ALG_NAME;
	}

	/**
	 * This method returns the blocksize, the algorithm uses. This method will
	 * normaly be called by the padding scheme. It must be assured, that this
	 * method is exclusivly called, when the algorithm is either in encryption
	 * or in decryption mode. The blocksize in Shacal is always 20 bytes.
	 * 
	 * @return the used blocksize
	 */
	protected int getCipherBlockSize() {
		return BLOCK_SIZE; // The blocksize is always 20 bytes
	}

	/**
	 * Returns the key size of the given key object. Checks whether the key
	 * object is an instance of <code>ShacalKey</code> or
	 * <code>SecretKeySpec</code>.
	 * 
	 * @param key
	 *            the key object
	 * @return the key size of the given key object.
	 * @throws InvalidKeyException
	 *             if key is invalid.
	 */
	public int getKeySize(Key key) throws InvalidKeyException {
		if (!((key instanceof ShacalKey) || (key instanceof SecretKeySpec))) {
			throw new InvalidKeyException("not a Shacal Key");
		}
		int keyLen = key.getEncoded().length;

		if (keyLen != 16 && keyLen != 24 && keyLen != 32 && keyLen != 40
				&& keyLen != 48 && keyLen != 64) {
			throw new InvalidKeyException("invalid key size");
		}
		return keyLen << 3;
	}

	/**
	 * This method implements the Shacal key schedule.
	 * 
	 * @param key
	 *            the byte array containing the key data
	 */
	private void keySchedule(byte[] key) {
		byte[] buffer = new byte[64];
		int n = key.length << 3;

		if ((n == 128) || (n == 192) || (n == 256) || (n == 320) || (n == 384)
				|| (n == 448)) {
			for (int i = 0; i < n >> 3; i++) {
				buffer[i] = key[i];
			}
			for (int i = n >> 3; i < 64; i++) {
				buffer[i] = 0;
			}
		} else if (n == 512) {
			System.arraycopy(key, 0, buffer, 0, key.length);
		}

		/* step a */

		w[0] = ((buffer[0] & 0xff) << 24) | (buffer[1] & 0xff) << 16
				| (buffer[2] & 0xff) << 8 | (buffer[3] & 0xff);
		w[1] = ((buffer[4] & 0xff) << 24) | (buffer[5] & 0xff) << 16
				| (buffer[6] & 0xff) << 8 | (buffer[7] & 0xff);
		w[2] = ((buffer[8] & 0xff) << 24) | (buffer[9] & 0xff) << 16
				| (buffer[10] & 0xff) << 8 | (buffer[11] & 0xff);
		w[3] = ((buffer[12] & 0xff) << 24) | (buffer[13] & 0xff) << 16
				| (buffer[14] & 0xff) << 8 | (buffer[15] & 0xff);
		w[4] = ((buffer[16] & 0xff) << 24) | (buffer[17] & 0xff) << 16
				| (buffer[18] & 0xff) << 8 | (buffer[19] & 0xff);
		w[5] = ((buffer[20] & 0xff) << 24) | (buffer[21] & 0xff) << 16
				| (buffer[22] & 0xff) << 8 | (buffer[23] & 0xff);
		w[6] = ((buffer[24] & 0xff) << 24) | (buffer[25] & 0xff) << 16
				| (buffer[26] & 0xff) << 8 | (buffer[27] & 0xff);
		w[7] = ((buffer[28] & 0xff) << 24) | (buffer[29] & 0xff) << 16
				| (buffer[30] & 0xff) << 8 | (buffer[31] & 0xff);
		w[8] = ((buffer[32] & 0xff) << 24) | (buffer[33] & 0xff) << 16
				| (buffer[34] & 0xff) << 8 | (buffer[35] & 0xff);
		w[9] = ((buffer[36] & 0xff) << 24) | (buffer[37] & 0xff) << 16
				| (buffer[38] & 0xff) << 8 | (buffer[39] & 0xff);
		w[10] = ((buffer[40] & 0xff) << 24) | (buffer[41] & 0xff) << 16
				| (buffer[42] & 0xff) << 8 | (buffer[43] & 0xff);
		w[11] = ((buffer[44] & 0xff) << 24) | (buffer[45] & 0xff) << 16
				| (buffer[46] & 0xff) << 8 | (buffer[47] & 0xff);
		w[12] = ((buffer[48] & 0xff) << 24) | (buffer[49] & 0xff) << 16
				| (buffer[50] & 0xff) << 8 | (buffer[51] & 0xff);
		w[13] = ((buffer[52] & 0xff) << 24) | (buffer[53] & 0xff) << 16
				| (buffer[54] & 0xff) << 8 | (buffer[55] & 0xff);
		w[14] = ((buffer[56] & 0xff) << 24) | (buffer[57] & 0xff) << 16
				| (buffer[58] & 0xff) << 8 | (buffer[59] & 0xff);
		w[15] = ((buffer[60] & 0xff) << 24) | (buffer[61] & 0xff) << 16
				| (buffer[62] & 0xff) << 8 | (buffer[63] & 0xff);

		/* step b */

		for (int i = 16; i < 80; i++) {
			int register;

			register = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
			// circular left shift by one bit
			w[i] = (register << 1) | (register >>> 31);
		}
	}

	/**
	 * This method guarantees the AlgorithmParameterSpec compatibility. As these
	 * are not used here it just calls the origin InitDecrypt method.
	 * 
	 * @param key
	 *            the SecretKey which has to be used to decrypt data.
	 * @param params
	 *            algorithmParameterSpec, not used for here
	 * 
	 * @throws InvalidKeyException
	 *             if the given key is inappropriate for initialising this
	 *             cipher.
	 */
	protected void initCipherEncrypt(SecretKey key,
			AlgorithmParameterSpec params) throws InvalidKeyException {
		// exception handling

		if (!((key instanceof ShacalKey) || (key instanceof SecretKeySpec))) {
			throw new InvalidKeyException("not a Shacal Key");
		}

		keySchedule(key.getEncoded());
	}

	/**
	 * This method guarantees the AlgorithmParameterSpec compatibility. As these
	 * are not used here it just calls the origin InitDecrypt method.
	 * 
	 * @param key
	 *            the SecretKey which has to be used to decrypt data.
	 * @param params
	 *            algorithmParameterSpec, not used for here
	 * @throws InvalidKeyException
	 *             if the key is invalid.
	 */
	protected void initCipherDecrypt(SecretKey key,
			AlgorithmParameterSpec params) throws InvalidKeyException {
		initCipherEncrypt(key, params);
	}

	/**
	 * This method decrypts a single block of data, and may only be called, if
	 * the block cipher is in decrytion mode. It has to be asured that the array
	 * <tt>in</tt> contains a whole block starting at <tt>inOffset</tt> and that
	 * <tt>out</tt> is large enough to hold an decrypted block starting at
	 * <tt>outOffset</tt>
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
		int a, b, c, d, e;
		int[] inputInt = new int[5];

		for (int i = 0; i < 5; i++) {
			inputInt[i] = BigEndianConversions.OS2IP(input, 4 * i + inOff);
		}

		a = inputInt[0];
		b = inputInt[1];
		c = inputInt[2];
		d = inputInt[3];
		e = inputInt[4];

		c = c >>> 30 | c << 2;
		a -= k4 + (b << 5 | b >>> 27) + (c ^ d ^ e) + w[79];
		d = d >>> 30 | d << 2;
		b -= k4 + (c << 5 | c >>> 27) + (d ^ e ^ a) + w[78];
		e = e >>> 30 | e << 2;
		c -= k4 + (d << 5 | d >>> 27) + (e ^ a ^ b) + w[77];
		a = a >>> 30 | a << 2;
		d -= k4 + (e << 5 | e >>> 27) + (a ^ b ^ c) + w[76];
		b = b >>> 30 | b << 2;
		e -= k4 + (a << 5 | a >>> 27) + (b ^ c ^ d) + w[75];

		c = c >>> 30 | c << 2;
		a -= k4 + (b << 5 | b >>> 27) + (c ^ d ^ e) + w[74];
		d = d >>> 30 | d << 2;
		b -= k4 + (c << 5 | c >>> 27) + (d ^ e ^ a) + w[73];
		e = e >>> 30 | e << 2;
		c -= k4 + (d << 5 | d >>> 27) + (e ^ a ^ b) + w[72];
		a = a >>> 30 | a << 2;
		d -= k4 + (e << 5 | e >>> 27) + (a ^ b ^ c) + w[71];
		b = b >>> 30 | b << 2;
		e -= k4 + (a << 5 | a >>> 27) + (b ^ c ^ d) + w[70];

		c = c >>> 30 | c << 2;
		a -= k4 + (b << 5 | b >>> 27) + (c ^ d ^ e) + w[69];
		d = d >>> 30 | d << 2;
		b -= k4 + (c << 5 | c >>> 27) + (d ^ e ^ a) + w[68];
		e = e >>> 30 | e << 2;
		c -= k4 + (d << 5 | d >>> 27) + (e ^ a ^ b) + w[67];
		a = a >>> 30 | a << 2;
		d -= k4 + (e << 5 | e >>> 27) + (a ^ b ^ c) + w[66];
		b = b >>> 30 | b << 2;
		e -= k4 + (a << 5 | a >>> 27) + (b ^ c ^ d) + w[65];

		c = c >>> 30 | c << 2;
		a -= k4 + (b << 5 | b >>> 27) + (c ^ d ^ e) + w[64];
		d = d >>> 30 | d << 2;
		b -= k4 + (c << 5 | c >>> 27) + (d ^ e ^ a) + w[63];
		e = e >>> 30 | e << 2;
		c -= k4 + (d << 5 | d >>> 27) + (e ^ a ^ b) + w[62];
		a = a >>> 30 | a << 2;
		d -= k4 + (e << 5 | e >>> 27) + (a ^ b ^ c) + w[61];
		b = b >>> 30 | b << 2;
		e -= k4 + (a << 5 | a >>> 27) + (b ^ c ^ d) + w[60];

		c = c >>> 30 | c << 2;
		a -= k3 + (b << 5 | b >>> 27) + (c & d | c & e | d & e) + w[59];
		d = d >>> 30 | d << 2;
		b -= k3 + (c << 5 | c >>> 27) + (d & e | d & a | e & a) + w[58];
		e = e >>> 30 | e << 2;
		c -= k3 + (d << 5 | d >>> 27) + (e & a | e & b | a & b) + w[57];
		a = a >>> 30 | a << 2;
		d -= k3 + (e << 5 | e >>> 27) + (a & b | a & c | b & c) + w[56];
		b = b >>> 30 | b << 2;
		e -= k3 + (a << 5 | a >>> 27) + (b & c | b & d | c & d) + w[55];

		c = c >>> 30 | c << 2;
		a -= k3 + (b << 5 | b >>> 27) + (c & d | c & e | d & e) + w[54];
		d = d >>> 30 | d << 2;
		b -= k3 + (c << 5 | c >>> 27) + (d & e | d & a | e & a) + w[53];
		e = e >>> 30 | e << 2;
		c -= k3 + (d << 5 | d >>> 27) + (e & a | e & b | a & b) + w[52];
		a = a >>> 30 | a << 2;
		d -= k3 + (e << 5 | e >>> 27) + (a & b | a & c | b & c) + w[51];
		b = b >>> 30 | b << 2;
		e -= k3 + (a << 5 | a >>> 27) + (b & c | b & d | c & d) + w[50];

		c = c >>> 30 | c << 2;
		a -= k3 + (b << 5 | b >>> 27) + (c & d | c & e | d & e) + w[49];
		d = d >>> 30 | d << 2;
		b -= k3 + (c << 5 | c >>> 27) + (d & e | d & a | e & a) + w[48];
		e = e >>> 30 | e << 2;
		c -= k3 + (d << 5 | d >>> 27) + (e & a | e & b | a & b) + w[47];
		a = a >>> 30 | a << 2;
		d -= k3 + (e << 5 | e >>> 27) + (a & b | a & c | b & c) + w[46];
		b = b >>> 30 | b << 2;
		e -= k3 + (a << 5 | a >>> 27) + (b & c | b & d | c & d) + w[45];

		c = c >>> 30 | c << 2;
		a -= k3 + (b << 5 | b >>> 27) + (c & d | c & e | d & e) + w[44];
		d = d >>> 30 | d << 2;
		b -= k3 + (c << 5 | c >>> 27) + (d & e | d & a | e & a) + w[43];
		e = e >>> 30 | e << 2;
		c -= k3 + (d << 5 | d >>> 27) + (e & a | e & b | a & b) + w[42];
		a = a >>> 30 | a << 2;
		d -= k3 + (e << 5 | e >>> 27) + (a & b | a & c | b & c) + w[41];
		b = b >>> 30 | b << 2;
		e -= k3 + (a << 5 | a >>> 27) + (b & c | b & d | c & d) + w[40];

		c = c >>> 30 | c << 2;
		a -= k2 + (b << 5 | b >>> 27) + (c ^ d ^ e) + w[39];
		d = d >>> 30 | d << 2;
		b -= k2 + (c << 5 | c >>> 27) + (d ^ e ^ a) + w[38];
		e = e >>> 30 | e << 2;
		c -= k2 + (d << 5 | d >>> 27) + (e ^ a ^ b) + w[37];
		a = a >>> 30 | a << 2;
		d -= k2 + (e << 5 | e >>> 27) + (a ^ b ^ c) + w[36];
		b = b >>> 30 | b << 2;
		e -= k2 + (a << 5 | a >>> 27) + (b ^ c ^ d) + w[35];

		c = c >>> 30 | c << 2;
		a -= k2 + (b << 5 | b >>> 27) + (c ^ d ^ e) + w[34];
		d = d >>> 30 | d << 2;
		b -= k2 + (c << 5 | c >>> 27) + (d ^ e ^ a) + w[33];
		e = e >>> 30 | e << 2;
		c -= k2 + (d << 5 | d >>> 27) + (e ^ a ^ b) + w[32];
		a = a >>> 30 | a << 2;
		d -= k2 + (e << 5 | e >>> 27) + (a ^ b ^ c) + w[31];
		b = b >>> 30 | b << 2;
		e -= k2 + (a << 5 | a >>> 27) + (b ^ c ^ d) + w[30];

		c = c >>> 30 | c << 2;
		a -= k2 + (b << 5 | b >>> 27) + (c ^ d ^ e) + w[29];
		d = d >>> 30 | d << 2;
		b -= k2 + (c << 5 | c >>> 27) + (d ^ e ^ a) + w[28];
		e = e >>> 30 | e << 2;
		c -= k2 + (d << 5 | d >>> 27) + (e ^ a ^ b) + w[27];
		a = a >>> 30 | a << 2;
		d -= k2 + (e << 5 | e >>> 27) + (a ^ b ^ c) + w[26];
		b = b >>> 30 | b << 2;
		e -= k2 + (a << 5 | a >>> 27) + (b ^ c ^ d) + w[25];

		c = c >>> 30 | c << 2;
		a -= k2 + (b << 5 | b >>> 27) + (c ^ d ^ e) + w[24];
		d = d >>> 30 | d << 2;
		b -= k2 + (c << 5 | c >>> 27) + (d ^ e ^ a) + w[23];
		e = e >>> 30 | e << 2;
		c -= k2 + (d << 5 | d >>> 27) + (e ^ a ^ b) + w[22];
		a = a >>> 30 | a << 2;
		d -= k2 + (e << 5 | e >>> 27) + (a ^ b ^ c) + w[21];
		b = b >>> 30 | b << 2;
		e -= k2 + (a << 5 | a >>> 27) + (b ^ c ^ d) + w[20];

		c = c >>> 30 | c << 2;
		a -= k1 + (b << 5 | b >>> 27) + (c & d | ~c & e) + w[19];
		d = d >>> 30 | d << 2;
		b -= k1 + (c << 5 | c >>> 27) + (d & e | ~d & a) + w[18];
		e = e >>> 30 | e << 2;
		c -= k1 + (d << 5 | d >>> 27) + (e & a | ~e & b) + w[17];
		a = a >>> 30 | a << 2;
		d -= k1 + (e << 5 | e >>> 27) + (a & b | ~a & c) + w[16];
		b = b >>> 30 | b << 2;
		e -= k1 + (a << 5 | a >>> 27) + (b & c | ~b & d) + w[15];

		c = c >>> 30 | c << 2;
		a -= k1 + (b << 5 | b >>> 27) + (c & d | ~c & e) + w[14];
		d = d >>> 30 | d << 2;
		b -= k1 + (c << 5 | c >>> 27) + (d & e | ~d & a) + w[13];
		e = e >>> 30 | e << 2;
		c -= k1 + (d << 5 | d >>> 27) + (e & a | ~e & b) + w[12];
		a = a >>> 30 | a << 2;
		d -= k1 + (e << 5 | e >>> 27) + (a & b | ~a & c) + w[11];
		b = b >>> 30 | b << 2;
		e -= k1 + (a << 5 | a >>> 27) + (b & c | ~b & d) + w[10];

		c = c >>> 30 | c << 2;
		a -= k1 + (b << 5 | b >>> 27) + (c & d | ~c & e) + w[9];
		d = d >>> 30 | d << 2;
		b -= k1 + (c << 5 | c >>> 27) + (d & e | ~d & a) + w[8];
		e = e >>> 30 | e << 2;
		c -= k1 + (d << 5 | d >>> 27) + (e & a | ~e & b) + w[7];
		a = a >>> 30 | a << 2;
		d -= k1 + (e << 5 | e >>> 27) + (a & b | ~a & c) + w[6];
		b = b >>> 30 | b << 2;
		e -= k1 + (a << 5 | a >>> 27) + (b & c | ~b & d) + w[5];

		c = c >>> 30 | c << 2;
		a -= k1 + (b << 5 | b >>> 27) + (c & d | ~c & e) + w[4];
		d = d >>> 30 | d << 2;
		b -= k1 + (c << 5 | c >>> 27) + (d & e | ~d & a) + w[3];
		e = e >>> 30 | e << 2;
		c -= k1 + (d << 5 | d >>> 27) + (e & a | ~e & b) + w[2];
		a = a >>> 30 | a << 2;
		d -= k1 + (e << 5 | e >>> 27) + (a & b | ~a & c) + w[1];
		b = b >>> 30 | b << 2;
		e -= k1 + (a << 5 | a >>> 27) + (b & c | ~b & d) + w[0];

		/* step e */

		inputInt[0] = a;
		inputInt[1] = b;
		inputInt[2] = c;
		inputInt[3] = d;
		inputInt[4] = e;

		for (int i = 0; i < 5; i++) {
			BigEndianConversions.I2OSP(inputInt[i], output, 4 * i + outOff);
		}
	}

	/**
	 * This method encrypts a single block of data, and may only be called, if
	 * the block cipher is in encrytion mode. It has to be asured that the array
	 * <tt>in</tt> contains a whole block starting at <tt>inOffset</tt> and that
	 * <tt>out</tt> is large enough to hold an encrypted block starting at
	 * <tt>outOffset</tt>
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
		int a, b, c, d, e;
		int[] inputInt = new int[5];

		for (int i = 0; i < 5; i++) {
			inputInt[i] = BigEndianConversions.OS2IP(input, 4 * i + inOff);
		}
		a = inputInt[0];
		b = inputInt[1];
		c = inputInt[2];
		d = inputInt[3];
		e = inputInt[4];

		/* step d */

		e += k1 + (a << 5 | a >>> 27) + (b & c | ~b & d) + w[0];
		b = b << 30 | b >>> 2;
		d += k1 + (e << 5 | e >>> 27) + (a & b | ~a & c) + w[1];
		a = a << 30 | a >>> 2;
		c += k1 + (d << 5 | d >>> 27) + (e & a | ~e & b) + w[2];
		e = e << 30 | e >>> 2;
		b += k1 + (c << 5 | c >>> 27) + (d & e | ~d & a) + w[3];
		d = d << 30 | d >>> 2;
		a += k1 + (b << 5 | b >>> 27) + (c & d | ~c & e) + w[4];
		c = c << 30 | c >>> 2;

		e += k1 + (a << 5 | a >>> 27) + (b & c | ~b & d) + w[5];
		b = b << 30 | b >>> 2;
		d += k1 + (e << 5 | e >>> 27) + (a & b | ~a & c) + w[6];
		a = a << 30 | a >>> 2;
		c += k1 + (d << 5 | d >>> 27) + (e & a | ~e & b) + w[7];
		e = e << 30 | e >>> 2;
		b += k1 + (c << 5 | c >>> 27) + (d & e | ~d & a) + w[8];
		d = d << 30 | d >>> 2;
		a += k1 + (b << 5 | b >>> 27) + (c & d | ~c & e) + w[9];
		c = c << 30 | c >>> 2;

		e += k1 + (a << 5 | a >>> 27) + (b & c | ~b & d) + w[10];
		b = b << 30 | b >>> 2;
		d += k1 + (e << 5 | e >>> 27) + (a & b | ~a & c) + w[11];
		a = a << 30 | a >>> 2;
		c += k1 + (d << 5 | d >>> 27) + (e & a | ~e & b) + w[12];
		e = e << 30 | e >>> 2;
		b += k1 + (c << 5 | c >>> 27) + (d & e | ~d & a) + w[13];
		d = d << 30 | d >>> 2;
		a += k1 + (b << 5 | b >>> 27) + (c & d | ~c & e) + w[14];
		c = c << 30 | c >>> 2;

		e += k1 + (a << 5 | a >>> 27) + (b & c | ~b & d) + w[15];
		b = b << 30 | b >>> 2;
		d += k1 + (e << 5 | e >>> 27) + (a & b | ~a & c) + w[16];
		a = a << 30 | a >>> 2;
		c += k1 + (d << 5 | d >>> 27) + (e & a | ~e & b) + w[17];
		e = e << 30 | e >>> 2;
		b += k1 + (c << 5 | c >>> 27) + (d & e | ~d & a) + w[18];
		d = d << 30 | d >>> 2;
		a += k1 + (b << 5 | b >>> 27) + (c & d | ~c & e) + w[19];
		c = c << 30 | c >>> 2;

		e += k2 + (a << 5 | a >>> 27) + (b ^ c ^ d) + w[20];
		b = b << 30 | b >>> 2;
		d += k2 + (e << 5 | e >>> 27) + (a ^ b ^ c) + w[21];
		a = a << 30 | a >>> 2;
		c += k2 + (d << 5 | d >>> 27) + (e ^ a ^ b) + w[22];
		e = e << 30 | e >>> 2;
		b += k2 + (c << 5 | c >>> 27) + (d ^ e ^ a) + w[23];
		d = d << 30 | d >>> 2;
		a += k2 + (b << 5 | b >>> 27) + (c ^ d ^ e) + w[24];
		c = c << 30 | c >>> 2;

		e += k2 + (a << 5 | a >>> 27) + (b ^ c ^ d) + w[25];
		b = b << 30 | b >>> 2;
		d += k2 + (e << 5 | e >>> 27) + (a ^ b ^ c) + w[26];
		a = a << 30 | a >>> 2;
		c += k2 + (d << 5 | d >>> 27) + (e ^ a ^ b) + w[27];
		e = e << 30 | e >>> 2;
		b += k2 + (c << 5 | c >>> 27) + (d ^ e ^ a) + w[28];
		d = d << 30 | d >>> 2;
		a += k2 + (b << 5 | b >>> 27) + (c ^ d ^ e) + w[29];
		c = c << 30 | c >>> 2;

		e += k2 + (a << 5 | a >>> 27) + (b ^ c ^ d) + w[30];
		b = b << 30 | b >>> 2;
		d += k2 + (e << 5 | e >>> 27) + (a ^ b ^ c) + w[31];
		a = a << 30 | a >>> 2;
		c += k2 + (d << 5 | d >>> 27) + (e ^ a ^ b) + w[32];
		e = e << 30 | e >>> 2;
		b += k2 + (c << 5 | c >>> 27) + (d ^ e ^ a) + w[33];
		d = d << 30 | d >>> 2;
		a += k2 + (b << 5 | b >>> 27) + (c ^ d ^ e) + w[34];
		c = c << 30 | c >>> 2;

		e += k2 + (a << 5 | a >>> 27) + (b ^ c ^ d) + w[35];
		b = b << 30 | b >>> 2;
		d += k2 + (e << 5 | e >>> 27) + (a ^ b ^ c) + w[36];
		a = a << 30 | a >>> 2;
		c += k2 + (d << 5 | d >>> 27) + (e ^ a ^ b) + w[37];
		e = e << 30 | e >>> 2;
		b += k2 + (c << 5 | c >>> 27) + (d ^ e ^ a) + w[38];
		d = d << 30 | d >>> 2;
		a += k2 + (b << 5 | b >>> 27) + (c ^ d ^ e) + w[39];
		c = c << 30 | c >>> 2;

		e += k3 + (a << 5 | a >>> 27) + (b & c | b & d | c & d) + w[40];
		b = b << 30 | b >>> 2;
		d += k3 + (e << 5 | e >>> 27) + (a & b | a & c | b & c) + w[41];
		a = a << 30 | a >>> 2;
		c += k3 + (d << 5 | d >>> 27) + (e & a | e & b | a & b) + w[42];
		e = e << 30 | e >>> 2;
		b += k3 + (c << 5 | c >>> 27) + (d & e | d & a | e & a) + w[43];
		d = d << 30 | d >>> 2;
		a += k3 + (b << 5 | b >>> 27) + (c & d | c & e | d & e) + w[44];
		c = c << 30 | c >>> 2;

		e += k3 + (a << 5 | a >>> 27) + (b & c | b & d | c & d) + w[45];
		b = b << 30 | b >>> 2;
		d += k3 + (e << 5 | e >>> 27) + (a & b | a & c | b & c) + w[46];
		a = a << 30 | a >>> 2;
		c += k3 + (d << 5 | d >>> 27) + (e & a | e & b | a & b) + w[47];
		e = e << 30 | e >>> 2;
		b += k3 + (c << 5 | c >>> 27) + (d & e | d & a | e & a) + w[48];
		d = d << 30 | d >>> 2;
		a += k3 + (b << 5 | b >>> 27) + (c & d | c & e | d & e) + w[49];
		c = c << 30 | c >>> 2;

		e += k3 + (a << 5 | a >>> 27) + (b & c | b & d | c & d) + w[50];
		b = b << 30 | b >>> 2;
		d += k3 + (e << 5 | e >>> 27) + (a & b | a & c | b & c) + w[51];
		a = a << 30 | a >>> 2;
		c += k3 + (d << 5 | d >>> 27) + (e & a | e & b | a & b) + w[52];
		e = e << 30 | e >>> 2;
		b += k3 + (c << 5 | c >>> 27) + (d & e | d & a | e & a) + w[53];
		d = d << 30 | d >>> 2;
		a += k3 + (b << 5 | b >>> 27) + (c & d | c & e | d & e) + w[54];
		c = c << 30 | c >>> 2;

		e += k3 + (a << 5 | a >>> 27) + (b & c | b & d | c & d) + w[55];
		b = b << 30 | b >>> 2;
		d += k3 + (e << 5 | e >>> 27) + (a & b | a & c | b & c) + w[56];
		a = a << 30 | a >>> 2;
		c += k3 + (d << 5 | d >>> 27) + (e & a | e & b | a & b) + w[57];
		e = e << 30 | e >>> 2;
		b += k3 + (c << 5 | c >>> 27) + (d & e | d & a | e & a) + w[58];
		d = d << 30 | d >>> 2;
		a += k3 + (b << 5 | b >>> 27) + (c & d | c & e | d & e) + w[59];
		c = c << 30 | c >>> 2;

		e += k4 + (a << 5 | a >>> 27) + (b ^ c ^ d) + w[60];
		b = b << 30 | b >>> 2;
		d += k4 + (e << 5 | e >>> 27) + (a ^ b ^ c) + w[61];
		a = a << 30 | a >>> 2;
		c += k4 + (d << 5 | d >>> 27) + (e ^ a ^ b) + w[62];
		e = e << 30 | e >>> 2;
		b += k4 + (c << 5 | c >>> 27) + (d ^ e ^ a) + w[63];
		d = d << 30 | d >>> 2;
		a += k4 + (b << 5 | b >>> 27) + (c ^ d ^ e) + w[64];
		c = c << 30 | c >>> 2;

		e += k4 + (a << 5 | a >>> 27) + (b ^ c ^ d) + w[65];
		b = b << 30 | b >>> 2;
		d += k4 + (e << 5 | e >>> 27) + (a ^ b ^ c) + w[66];
		a = a << 30 | a >>> 2;
		c += k4 + (d << 5 | d >>> 27) + (e ^ a ^ b) + w[67];
		e = e << 30 | e >>> 2;
		b += k4 + (c << 5 | c >>> 27) + (d ^ e ^ a) + w[68];
		d = d << 30 | d >>> 2;
		a += k4 + (b << 5 | b >>> 27) + (c ^ d ^ e) + w[69];
		c = c << 30 | c >>> 2;

		e += k4 + (a << 5 | a >>> 27) + (b ^ c ^ d) + w[70];
		b = b << 30 | b >>> 2;
		d += k4 + (e << 5 | e >>> 27) + (a ^ b ^ c) + w[71];
		a = a << 30 | a >>> 2;
		c += k4 + (d << 5 | d >>> 27) + (e ^ a ^ b) + w[72];
		e = e << 30 | e >>> 2;
		b += k4 + (c << 5 | c >>> 27) + (d ^ e ^ a) + w[73];
		d = d << 30 | d >>> 2;
		a += k4 + (b << 5 | b >>> 27) + (c ^ d ^ e) + w[74];
		c = c << 30 | c >>> 2;

		e += k4 + (a << 5 | a >>> 27) + (b ^ c ^ d) + w[75];
		b = b << 30 | b >>> 2;
		d += k4 + (e << 5 | e >>> 27) + (a ^ b ^ c) + w[76];
		a = a << 30 | a >>> 2;
		c += k4 + (d << 5 | d >>> 27) + (e ^ a ^ b) + w[77];
		e = e << 30 | e >>> 2;
		b += k4 + (c << 5 | c >>> 27) + (d ^ e ^ a) + w[78];
		d = d << 30 | d >>> 2;
		a += k4 + (b << 5 | b >>> 27) + (c ^ d ^ e) + w[79];
		c = c << 30 | c >>> 2;

		/* step e */

		inputInt[0] = a;
		inputInt[1] = b;
		inputInt[2] = c;
		inputInt[3] = d;
		inputInt[4] = e;

		for (int i = 0; i < 5; i++) {
			BigEndianConversions.I2OSP(inputInt[i], output, 4 * i + outOff);
		}
	}

}
