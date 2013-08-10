/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.saferplusplus;

import de.flexiprovider.api.BlockCipher;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.keys.Key;
import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.api.keys.SecretKeySpec;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;

/**
 * This class implements the SAFER++ block cipher as specified in 'Nomination of
 * SAFER++ as Candidate Algorithm for the new European Schemes for Signatures,
 * Integrity and Encryption (NESSIE)' (26 September 2000)
 * <p>
 * SAFER++ is a cipher based on the existing SAFER family of ciphers. It
 * provides for a standard block size of 128 bits and allows user-selected-keys
 * to be either 128 or 256 bits long. The SAFER class of ciphers is are not
 * Feistel network based but they rather are transformation/substitution
 * ciphers. SAFER++ operates on a per byte basis. The most significant change to
 * the SAFER+ cipher is the replacement of the invertible 16x16 matrix being
 * previously used for diffusion by four 4x4 Pseudo-Hadamard- Transformation
 * matrices.
 * <p>
 * The legacy version of SAFER++ supporting a block size of 64 bits together
 * with 128 bit keys is currently <b>not supported</b>.
 * 
 * @author Ralf-Philipp Weinmann
 */
public class SAFERPlusPlus extends BlockCipher {

	/**
	 * The algorithm name.
	 */
	public static final String ALG_NAME = "SAFER++";

	/**
	 * Block size is 16 bytes. TODO legacy block size of 64 bits currently not
	 * supported.
	 */
	private static final int blockSize = 16;

	/**
	 * Number of rounds to iterate round function (7 for 128 bit keys, 10 for
	 * 256 bit keys)
	 */
	private int rounds;

	private int[] x = new int[16];

	private int[] x2 = new int[16];

	/**
	 * Array of round subkeys
	 */
	private int[][] subKeys = new int[21][16];

	/**
	 * Lookup table for 45^x mod 257
	 */
	private int[] expTable = new int[256];

	/**
	 * Lookup table for log45(x) mod 257
	 */
	private int[] logTable = new int[256];

	/**
	 * Bias words for randomizing the round subkeys
	 */
	private int[][] biasTable = new int[22][16];

	/**
	 * Default constructor
	 */
	public SAFERPlusPlus() {
		initCipher();
	}

	/**
	 * @return the name of this cipher
	 */
	public String getName() {
		return ALG_NAME;
	}

	/**
	 * Returns the key size of the given key object. Checks whether the key
	 * object is an instance of <tt>SAFERPlusPlusKey</tt> or
	 * <tt>SecretKeySpec</tt> and whether the key size is within the specified
	 * range for SAFER++. 128 and 256 bit keys are allowed.
	 * 
	 * @param key
	 *            the key object
	 * @return the key size of the given key object.
	 * @throws InvalidKeyException
	 *             if key is invalid.
	 */
	public int getKeySize(Key key) throws InvalidKeyException {
		if (!((key instanceof SAFERPlusPlusKey) || (key instanceof SecretKeySpec))) {
			throw new InvalidKeyException("not a SAFER+ key.");
		}

		int keyLen = key.getEncoded().length;

		// check key size
		if (keyLen != 16 && keyLen != 32) {
			throw new InvalidKeyException("invalid key size");
		}

		return keyLen << 3;
	}

	/**
	 * Return the blocksize the algorithm uses. It is usually called by the
	 * padding scheme.
	 * 
	 * @return the used blocksize in <b>bytes</b>
	 */
	public int getCipherBlockSize() {
		return blockSize;
	}

	/**
	 * Dummy method to stay compatible with the API. the
	 * <tt>AlgorithmParameterSpec</tt> argument is not actually used here.
	 * 
	 * @param key
	 *            - the SecretKey which has to be used to decrypt data.
	 * @param paramSpec
	 *            - algorithmParameterSpec, not used for here
	 * @throws InvalidKeyException
	 *             if the given key is inappropriate for initialising this
	 *             cipher.
	 */
	protected void initCipherEncrypt(SecretKey key,
			AlgorithmParameterSpec paramSpec) throws InvalidKeyException {
		if (!(key instanceof SAFERPlusPlusKey)) {
			throw new InvalidKeyException("unsupported type");
		}

		keySchedule(key.getEncoded());
	}

	/**
	 * Dummy method to stay compatible with the API. the
	 * <tt>AlgorithmParameterSpec</tt> argument is not actually used here.
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

	private void keySchedule(byte[] key) throws InvalidKeyException {
		int[] expandedKey = new int[17];
		int i, j;

		// check key size
		if (key.length != 16 && key.length != 32) {
			throw new InvalidKeyException("invalid key size: "
					+ (key.length << 3) + " bits.");
		}
		// calculate odd-index subkeys
		if (key.length == 16 || key.length == 32) {
			for (i = 0; i < 16; i++) {
				expandedKey[i] = key[i] & 0xff;
			}
		}

		// compute parity byte (bytewise xor)
		expandedKey[16] = 0;
		for (i = 0; i < 16; i++) {
			expandedKey[16] ^= expandedKey[i];
		}

		for (i = 1; i <= 21; i += 2) {
			for (j = 0; j < 16; j++) {
				subKeys[i - 1][j] = (expandedKey[(j + i - 1) % 17] + biasTable[i - 1][j]) & 0xff;
			}

			// rotate each byte 6 bits left
			for (j = 0; j < 17; j++) {
				expandedKey[j] = (expandedKey[j] << 6 | expandedKey[j] >> 2) & 0xff;
			}
		}

		// calculate even-index subkeys
		if (key.length == 32) {
			for (i = 0; i < 16; i++) {
				expandedKey[i] = key[i + 16] & 0xff;
			}
			// set number of rounds to 10 for 256 bit key
			rounds = 10;
		} else if (key.length == 16) {
			for (i = 0; i < 16; i++) {
				expandedKey[i] = key[i] & 0xff;
			}
			// set number of rounds to 7 for 128 bit key
			rounds = 7;
		}

		// compute parity byte (bytewise xor)
		expandedKey[16] = 0;
		for (i = 0; i < 16; i++) {
			expandedKey[16] ^= expandedKey[i];
		}

		// rotate each byte 3 bits left
		for (j = 0; j < 17; j++) {
			expandedKey[j] = (expandedKey[j] << 3 | expandedKey[j] >> 5) & 0xff;
		}

		for (i = 2; i <= 20; i += 2) {
			for (j = 0; j < 16; j++) {
				subKeys[i - 1][j] = (expandedKey[(j + i - 1) % 17] + biasTable[i - 1][j]) & 0xff;
			}

			// rotate each byte 6 bits left
			for (j = 0; j < 17; j++) {
				expandedKey[j] = (expandedKey[j] << 6 | expandedKey[j] >> 2) & 0xff;
			}
		}

		// wipe expanded key structure
		for (i = 0; i < 17; i++) {
			expandedKey[i] = 0;
		}
	}

	/**
	 * This method encrypts a single block of data. The array <tt>in</tt> must
	 * contain a whole block starting at <tt>inOffset</tt> and <tt>out</tt> must
	 * be large enough to hold an encrypted block starting at <tt>outOffset</tt>
	 * .
	 * 
	 * @param in
	 *            array of bytes containing the plaintext to be encrypted
	 * @param inOffset
	 *            index in array <tt>in</tt> where the plaintext block starts
	 * @param out
	 *            array of bytes which will contain the ciphertext starting at
	 *            <tt>outOffset</tt>
	 * @param outOffset
	 *            index in array <tt>out</tt> where the ciphertext block will
	 *            start
	 */
	protected void singleBlockEncrypt(byte[] in, int inOffset, byte[] out,
			int outOffset) {
		int i, lastidx = rounds << 1;

		for (i = 0; i < 16; i++) {
			x[i] = in[inOffset + i] & 0xff;
		}

		// iterate cipher round function
		for (i = 0; i < rounds; i++) {
			roundFunctionEncrypt(subKeys[i << 1], subKeys[(i << 1) + 1]);
		}

		// apply output transformation
		out[outOffset++] = (byte) (x[0] ^ subKeys[lastidx][0]);
		out[outOffset++] = (byte) (x[1] + subKeys[lastidx][1]);
		out[outOffset++] = (byte) (x[2] + subKeys[lastidx][2]);
		out[outOffset++] = (byte) (x[3] ^ subKeys[lastidx][3]);
		out[outOffset++] = (byte) (x[4] ^ subKeys[lastidx][4]);
		out[outOffset++] = (byte) (x[5] + subKeys[lastidx][5]);
		out[outOffset++] = (byte) (x[6] + subKeys[lastidx][6]);
		out[outOffset++] = (byte) (x[7] ^ subKeys[lastidx][7]);
		out[outOffset++] = (byte) (x[8] ^ subKeys[lastidx][8]);
		out[outOffset++] = (byte) (x[9] + subKeys[lastidx][9]);
		out[outOffset++] = (byte) (x[10] + subKeys[lastidx][10]);
		out[outOffset++] = (byte) (x[11] ^ subKeys[lastidx][11]);
		out[outOffset++] = (byte) (x[12] ^ subKeys[lastidx][12]);
		out[outOffset++] = (byte) (x[13] + subKeys[lastidx][13]);
		out[outOffset++] = (byte) (x[14] + subKeys[lastidx][14]);
		out[outOffset] = (byte) (x[15] ^ subKeys[lastidx][15]);
	}

	/**
	 * This method decrypts a single block of data. The array <tt>input</tt>
	 * must contain a whole block starting at <tt>inOff</tt> and <tt>output</tt>
	 * must be large enough to hold an encrypted block starting at
	 * <tt>outOff</tt>.
	 * 
	 * @param input
	 *            array of bytes containig the ciphertext to be decrypted
	 * @param inOff
	 *            index in array <tt>in</tt> where the ciphertext block starts
	 * @param output
	 *            array of bytes which will contain the plaintext starting at
	 *            <tt>outOffset</tt>
	 * @param outOff
	 *            index in array <tt>out</tt> where the plaintext block will
	 *            start
	 */
	protected void singleBlockDecrypt(byte[] input, int inOff, byte[] output,
			int outOff) {
		int i, lastidx = rounds << 1;

		// undo output transformation
		x[0] = (input[inOff++] ^ subKeys[lastidx][0]) & 0xff;
		x[1] = (input[inOff++] - subKeys[lastidx][1]) & 0xff;
		x[2] = (input[inOff++] - subKeys[lastidx][2]) & 0xff;
		x[3] = (input[inOff++] ^ subKeys[lastidx][3]) & 0xff;
		x[4] = (input[inOff++] ^ subKeys[lastidx][4]) & 0xff;
		x[5] = (input[inOff++] - subKeys[lastidx][5]) & 0xff;
		x[6] = (input[inOff++] - subKeys[lastidx][6]) & 0xff;
		x[7] = (input[inOff++] ^ subKeys[lastidx][7]) & 0xff;
		x[8] = (input[inOff++] ^ subKeys[lastidx][8]) & 0xff;
		x[9] = (input[inOff++] - subKeys[lastidx][9]) & 0xff;
		x[10] = (input[inOff++] - subKeys[lastidx][10]) & 0xff;
		x[11] = (input[inOff++] ^ subKeys[lastidx][11]) & 0xff;
		x[12] = (input[inOff++] ^ subKeys[lastidx][12]) & 0xff;
		x[13] = (input[inOff++] - subKeys[lastidx][13]) & 0xff;
		x[14] = (input[inOff++] - subKeys[lastidx][14]) & 0xff;
		x[15] = (input[inOff++] ^ subKeys[lastidx][15]) & 0xff;

		// iterate inverse cipher round function
		for (i = rounds - 1; i >= 0; i--) {
			roundFunctionDecrypt(subKeys[(i << 1) + 1], subKeys[i << 1]);
		}

		for (i = 0; i < 16; i++) {
			output[outOff + i] = (byte) x[i];
		}
	}

	// //////////////////////////////////////////////////////////////////////////

	private void initCipher() {
		int i, j;

		// calculate values (45^x mod 257) mod 256
		// n.b.: the additional mod 256 only causes the value 256 to be
		// mapped to 0
		expTable[0] = 1;
		for (i = 1; i < 256; i++) {
			expTable[i] = (expTable[i - 1] * 45) % 257;
		}
		expTable[128] = 0;

		// calculate log45(x) mod 257
		// however log45(0) mod 257 is defined to be 128
		// so that expTable and logTable are inverse to each other
		for (i = 0; i < 256; i++) {
			logTable[expTable[i]] = i;
		}

		// calculate biases for key scheduling
		// strictly speaking B1 (the first row of the table) is not
		// used, we calculate it anyway.
		// the first 15 rows are calculated as 45^(45^(17*i+j)), i being
		// the row, j being the column
		for (i = 2; i <= 15; i++) {
			for (j = 1; j <= 16; j++) {
				biasTable[i - 1][j - 1] = expTable[expTable[(17 * i + j) & 0xff]];
			}
		}

		// rows 16-21 are calulcated as 45^(17*i+j), i and j defined as above
		for (i = 16; i <= 21; i++) {
			for (j = 1; j <= 16; j++) {
				biasTable[i - 1][j - 1] = expTable[(17 * i + j) & 0xff];
			}
		}
	}

	private void shuffle4PHT(int[] in, int[] out, int inoff1, int inoff2,
			int inoff3, int inoff4, int outoff) {
		int a, b, c, d;

		a = in[inoff1];
		b = in[inoff2];
		c = in[inoff3];
		d = in[inoff4];

		d += a + b + c;

		out[outoff] = (a + d) & 0xff;
		out[outoff + 1] = (b + d) & 0xff;
		out[outoff + 2] = (c + d) & 0xff;
		out[outoff + 3] = d & 0xff;
	}

	private void inverseShuffle4IPHT(int[] in, int[] out, int inoff,
			int outoff1, int outoff2, int outoff3, int outoff4) {
		int a, b, c, d;

		a = in[inoff];
		b = in[inoff + 1];
		c = in[inoff + 2];
		d = in[inoff + 3];

		a = (a - d) & 0xff;
		b = (b - d) & 0xff;
		c = (c - d) & 0xff;

		out[outoff1] = a;
		out[outoff2] = b;
		out[outoff3] = c;
		out[outoff4] = (d - a - b - c) & 0xff;
	}

	private void roundFunctionEncrypt(int[] subKey1, int[] subKey2) {
		// key-controlled substitution (all 3 layers folded into one)
		x[0] = (expTable[x[0] ^ subKey1[0] & 0xff] + subKey2[0]) & 0xff;
		x[1] = (logTable[x[1] + subKey1[1] & 0xff] ^ subKey2[1]) & 0xff;
		x[2] = (logTable[x[2] + subKey1[2] & 0xff] ^ subKey2[2]) & 0xff;
		x[3] = (expTable[x[3] ^ subKey1[3] & 0xff] + subKey2[3]) & 0xff;
		x[4] = (expTable[x[4] ^ subKey1[4] & 0xff] + subKey2[4]) & 0xff;
		x[5] = (logTable[x[5] + subKey1[5] & 0xff] ^ subKey2[5]) & 0xff;
		x[6] = (logTable[x[6] + subKey1[6] & 0xff] ^ subKey2[6]) & 0xff;
		x[7] = (expTable[x[7] ^ subKey1[7] & 0xff] + subKey2[7]) & 0xff;
		x[8] = (expTable[x[8] ^ subKey1[8] & 0xff] + subKey2[8]) & 0xff;
		x[9] = (logTable[x[9] + subKey1[9] & 0xff] ^ subKey2[9]) & 0xff;
		x[10] = (logTable[x[10] + subKey1[10] & 0xff] ^ subKey2[10]) & 0xff;
		x[11] = (expTable[x[11] ^ subKey1[11] & 0xff] + subKey2[11]) & 0xff;
		x[12] = (expTable[x[12] ^ subKey1[12] & 0xff] + subKey2[12]) & 0xff;
		x[13] = (logTable[x[13] + subKey1[13] & 0xff] ^ subKey2[13]) & 0xff;
		x[14] = (logTable[x[14] + subKey1[14] & 0xff] ^ subKey2[14]) & 0xff;
		x[15] = (expTable[x[15] ^ subKey1[15] & 0xff] + subKey2[15]) & 0xff;

		// linear transformation
		// pre-shuffle and application of 4x 4-PHT
		shuffle4PHT(x, x2, 8, 5, 2, 15, 0);
		shuffle4PHT(x, x2, 0, 13, 10, 7, 4);
		shuffle4PHT(x, x2, 4, 1, 14, 11, 8);
		shuffle4PHT(x, x2, 12, 9, 6, 3, 12);

		// mid-shuffle and application of 4x 4-PHT
		shuffle4PHT(x2, x, 8, 5, 2, 15, 0);
		shuffle4PHT(x2, x, 0, 13, 10, 7, 4);
		shuffle4PHT(x2, x, 4, 1, 14, 11, 8);
		shuffle4PHT(x2, x, 12, 9, 6, 3, 12);
	}

	private void roundFunctionDecrypt(int[] subKey1, int[] subKey2) {
		// linear transformation (inverse)
		// apply 4x inverted 4-PHT and undo mid-shuffle
		inverseShuffle4IPHT(x, x2, 0, 8, 5, 2, 15);
		inverseShuffle4IPHT(x, x2, 4, 0, 13, 10, 7);
		inverseShuffle4IPHT(x, x2, 8, 4, 1, 14, 11);
		inverseShuffle4IPHT(x, x2, 12, 12, 9, 6, 3);

		// apply 4x inverted 4-PHT and undo pre-shuffle
		inverseShuffle4IPHT(x2, x, 0, 8, 5, 2, 15);
		inverseShuffle4IPHT(x2, x, 4, 0, 13, 10, 7);
		inverseShuffle4IPHT(x2, x, 8, 4, 1, 14, 11);
		inverseShuffle4IPHT(x2, x, 12, 12, 9, 6, 3);

		// key-controlled substitution (all 3 layers folded into one)
		x[0] = (logTable[x[0] - subKey1[0] & 0xff] ^ subKey2[0]) & 0xff;
		x[1] = (expTable[x[1] ^ subKey1[1] & 0xff] - subKey2[1]) & 0xff;
		x[2] = (expTable[x[2] ^ subKey1[2] & 0xff] - subKey2[2]) & 0xff;
		x[3] = (logTable[x[3] - subKey1[3] & 0xff] ^ subKey2[3]) & 0xff;
		x[4] = (logTable[x[4] - subKey1[4] & 0xff] ^ subKey2[4]) & 0xff;
		x[5] = (expTable[x[5] ^ subKey1[5] & 0xff] - subKey2[5]) & 0xff;
		x[6] = (expTable[x[6] ^ subKey1[6] & 0xff] - subKey2[6]) & 0xff;
		x[7] = (logTable[x[7] - subKey1[7] & 0xff] ^ subKey2[7]) & 0xff;
		x[8] = (logTable[x[8] - subKey1[8] & 0xff] ^ subKey2[8]) & 0xff;
		x[9] = (expTable[x[9] ^ subKey1[9] & 0xff] - subKey2[9]) & 0xff;
		x[10] = (expTable[x[10] ^ subKey1[10] & 0xff] - subKey2[10]) & 0xff;
		x[11] = (logTable[x[11] - subKey1[11] & 0xff] ^ subKey2[11]) & 0xff;
		x[12] = (logTable[x[12] - subKey1[12] & 0xff] ^ subKey2[12]) & 0xff;
		x[13] = (expTable[x[13] ^ subKey1[13] & 0xff] - subKey2[13]) & 0xff;
		x[14] = (expTable[x[14] ^ subKey1[14] & 0xff] - subKey2[14]) & 0xff;
		x[15] = (logTable[x[15] - subKey1[15] & 0xff] ^ subKey2[15]) & 0xff;
	}

}
