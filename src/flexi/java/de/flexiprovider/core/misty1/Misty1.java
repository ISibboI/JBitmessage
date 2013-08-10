/*
 * Copyright (c) 1998-2007 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */
package de.flexiprovider.core.misty1;

import de.flexiprovider.api.BlockCipher;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.keys.Key;
import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.api.keys.SecretKeySpec;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.util.BigEndianConversions;

/**
 * Misty1 is 64-bit symmetric block cipher with a Feistel structure, jointly
 * developed by Matsui Mitsuru, Ichikawa Tetsuya, Sorimachi Toru, Tokita Toshio,
 * and Yamagishi Atsuhiro for the Mitsubishi Electric Corporation. It supports
 * 128 bit keys. Encrypting and decryption of a block of data is achieved in 8
 * rounds (more generally a multiple of 4 rounds).
 * 
 * For more information, <a
 * href="http://www.security.melco.co.jp/SecWWW/MISTY/MISTY.htm">see here</a>.
 * 
 * @author Paul Nguentcheu
 */
public class Misty1 extends BlockCipher {

	/**
	 * The algorithm name.
	 */
	public static final String ALG_NAME = "Misty1";

	private static final int[] S7 = { 27, 50, 51, 90, 59, 16, 23, 84, 91, 26,
			114, 115, 107, 44, 102, 73, 31, 36, 19, 108, 55, 46, 63, 74, 93,
			15, 64, 86, 37, 81, 28, 4, 11, 70, 32, 13, 123, 53, 68, 66, 43, 30,
			65, 20, 75, 121, 21, 111, 14, 85, 9, 54, 116, 12, 103, 83, 40, 10,
			126, 56, 2, 7, 96, 41, 25, 18, 101, 47, 48, 57, 8, 104, 95, 120,
			42, 76, 100, 69, 117, 61, 89, 72, 3, 87, 124, 79, 98, 60, 29, 33,
			94, 39, 106, 112, 77, 58, 1, 109, 110, 99, 24, 119, 35, 5, 38, 118,
			0, 49, 45, 122, 127, 97, 80, 34, 17, 6, 71, 22, 82, 78, 113, 62,
			105, 67, 52, 92, 88, 125 };

	private static final int[] S9 = { 451, 203, 339, 415, 483, 233, 251, 53,
			385, 185, 279, 491, 307, 9, 45, 211, 199, 330, 55, 126, 235, 356,
			403, 472, 163, 286, 85, 44, 29, 418, 355, 280, 331, 338, 466, 15,
			43, 48, 314, 229, 273, 312, 398, 99, 227, 200, 500, 27, 1, 157,
			248, 416, 365, 499, 28, 326, 125, 209, 130, 490, 387, 301, 244,
			414, 467, 221, 482, 296, 480, 236, 89, 145, 17, 303, 38, 220, 176,
			396, 271, 503, 231, 364, 182, 249, 216, 337, 257, 332, 259, 184,
			340, 299, 430, 23, 113, 12, 71, 88, 127, 420, 308, 297, 132, 349,
			413, 434, 419, 72, 124, 81, 458, 35, 317, 423, 357, 59, 66, 218,
			402, 206, 193, 107, 159, 497, 300, 388, 250, 406, 481, 361, 381,
			49, 384, 266, 148, 474, 390, 318, 284, 96, 373, 463, 103, 281, 101,
			104, 153, 336, 8, 7, 380, 183, 36, 25, 222, 295, 219, 228, 425, 82,
			265, 144, 412, 449, 40, 435, 309, 362, 374, 223, 485, 392, 197,
			366, 478, 433, 195, 479, 54, 238, 494, 240, 147, 73, 154, 438, 105,
			129, 293, 11, 94, 180, 329, 455, 372, 62, 315, 439, 142, 454, 174,
			16, 149, 495, 78, 242, 509, 133, 253, 246, 160, 367, 131, 138, 342,
			155, 316, 263, 359, 152, 464, 489, 3, 510, 189, 290, 137, 210, 399,
			18, 51, 106, 322, 237, 368, 283, 226, 335, 344, 305, 327, 93, 275,
			461, 121, 353, 421, 377, 158, 436, 204, 34, 306, 26, 232, 4, 391,
			493, 407, 57, 447, 471, 39, 395, 198, 156, 208, 334, 108, 52, 498,
			110, 202, 37, 186, 401, 254, 19, 262, 47, 429, 370, 475, 192, 267,
			470, 245, 492, 269, 118, 276, 427, 117, 268, 484, 345, 84, 287, 75,
			196, 446, 247, 41, 164, 14, 496, 119, 77, 378, 134, 139, 179, 369,
			191, 270, 260, 151, 347, 352, 360, 215, 187, 102, 462, 252, 146,
			453, 111, 22, 74, 161, 313, 175, 241, 400, 10, 426, 323, 379, 86,
			397, 358, 212, 507, 333, 404, 410, 135, 504, 291, 167, 440, 321,
			60, 505, 320, 42, 341, 282, 417, 408, 213, 294, 431, 97, 302, 343,
			476, 114, 394, 170, 150, 277, 239, 69, 123, 141, 325, 83, 95, 376,
			178, 46, 32, 469, 63, 457, 487, 428, 68, 56, 20, 177, 363, 171,
			181, 90, 386, 456, 468, 24, 375, 100, 207, 109, 256, 409, 304, 346,
			5, 288, 443, 445, 224, 79, 214, 319, 452, 298, 21, 6, 255, 411,
			166, 67, 136, 80, 351, 488, 289, 115, 382, 188, 194, 201, 371, 393,
			501, 116, 460, 486, 424, 405, 31, 65, 13, 442, 50, 61, 465, 128,
			168, 87, 441, 354, 328, 217, 261, 98, 122, 33, 511, 274, 264, 448,
			169, 285, 432, 422, 205, 243, 92, 258, 91, 473, 324, 502, 173, 165,
			58, 459, 310, 383, 70, 225, 30, 477, 230, 311, 506, 389, 140, 143,
			64, 437, 190, 120, 0, 172, 272, 350, 292, 2, 444, 162, 234, 112,
			508, 278, 348, 76, 450 };

	private final int[] keys = new int[32];

	// Block size is 8 bytes.
	private static final int blockSize = 8;

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
	 * or in decryption mode. The blocksize in misty-1 is always 8 bytes.
	 * 
	 * @return the used blocksize
	 */
	protected final int getCipherBlockSize() {
		return blockSize;
	}

	/**
	 * Returns the key size of the given key object. Checks whether the key
	 * object is an instance of <code>Misty1Key</code> or
	 * <code>SecretKeySpec</code> and whether the key size is within the
	 * specified range for Misty1. Only 128 bit keys are allowed.
	 * 
	 * @param key
	 *            the key object
	 * @return the key size of the given key object.
	 * @throws InvalidKeyException
	 *             if key is invalid.
	 */
	public int getKeySize(Key key) throws InvalidKeyException {
		if (!((key instanceof Misty1Key) || (key instanceof SecretKeySpec))) {
			throw new InvalidKeyException("not a Misty-1 Key");
		}
		int keyLen = key.getEncoded().length;
		if (keyLen != 16) {
			throw new InvalidKeyException("invalid length");
		}
		return keyLen << 3;
	}

	/**
	 * This method initializes the block cipher with a given key for data
	 * encryption.
	 * 
	 * @param key
	 *            SecretKey to be used to encrypt data
	 * @param params
	 *            AlgorithmParamterSpec to be used with this algorithm
	 * @throws InvalidKeyException
	 *             if the given key is illegal for this cipher
	 */
	protected final void initCipherEncrypt(SecretKey key,
			AlgorithmParameterSpec params) throws InvalidKeyException {
		if (!(key instanceof Misty1Key)) {
			throw new InvalidKeyException("not a Misty-1 Key");
		}
		keyExpansion(key.getEncoded());
	}

	/**
	 * This method initializes the block cipher with a given key for data
	 * decryption.
	 * 
	 * @param key
	 *            SecretKey to be used to decrypt data
	 * @param params
	 *            AlgorithmParamterSpec to be used with this algorithm
	 * @throws InvalidKeyException
	 *             if the given key is illegal for this cipher
	 */
	protected final void initCipherDecrypt(SecretKey key,
			AlgorithmParameterSpec params) throws InvalidKeyException {
		initCipherEncrypt(key, params);
	}

	/**
	 * This method implements the Misty1 key expansion.
	 * 
	 * @param key
	 *            An array of bytes containing the key data
	 * 
	 */
	private void keyExpansion(byte[] key) {
		byte[] out = new byte[4];
		keys[0] = ((key[0] & 0xff) << 8) | (key[1] & 0xff);
		keys[1] = ((key[2] & 0xff) << 8) | (key[3] & 0xff);
		keys[2] = ((key[4] & 0xff) << 8) | (key[5] & 0xff);
		keys[3] = ((key[6] & 0xff) << 8) | (key[7] & 0xff);
		keys[4] = ((key[8] & 0xff) << 8) | (key[9] & 0xff);
		keys[5] = ((key[10] & 0xff) << 8) | (key[11] & 0xff);
		keys[6] = ((key[12] & 0xff) << 8) | (key[13] & 0xff);
		keys[7] = ((key[14] & 0xff) << 8) | (key[15] & 0xff);

		for (int i = 0; i < 8; i++) {
			keys[i + 8] = FI(keys[i], keys[(i + 1) & 7]);
			// keys[i + 16] = keys[i + 8] & 0x1ff;
			// keys[i + 24] = keys[i + 8] >>> 9;
		}
		BigEndianConversions.I2OSP(keys[15], out, 0);
	}

	/**
	 * This method encrypts a single block of data.
	 * 
	 * The array <code>in</code> must contain a whole block starting at
	 * <code>inOffset</code> and <code>out</code> must be large enough to hold
	 * an encrypted block starting at <code>outOffset</code>.
	 * 
	 * @param input
	 *            array of bytes containing the plaintext to be encrypted
	 * @param inOff
	 *            index in array in, where the plaintext block starts
	 * @param output
	 *            array of bytes which will contain the ciphertext starting at
	 *            outOffset
	 * @param outOff
	 *            index in array out, where the ciphertext block will start
	 */
	protected final void singleBlockEncrypt(byte[] input, int inOff,
			byte[] output, int outOff) {

		int D0 = BigEndianConversions.OS2IP(input, 0 + inOff);
		int D1 = BigEndianConversions.OS2IP(input, 4 + inOff);

		// 0 round
		D0 = FL(D0, 0);
		D1 = FL(D1, 1);
		D1 = D1 ^ FO(D0, 0);
		// 1 round
		D0 = D0 ^ FO(D1, 1);
		// 2 round
		D0 = FL(D0, 2);
		D1 = FL(D1, 3);
		D1 = D1 ^ FO(D0, 2);
		// 3 round
		D0 = D0 ^ FO(D1, 3);
		// 4 round
		D0 = FL(D0, 4);
		D1 = FL(D1, 5);
		D1 = D1 ^ FO(D0, 4);
		// 5 round
		D0 = D0 ^ FO(D1, 5);
		// 6 round
		D0 = FL(D0, 6);
		D1 = FL(D1, 7);
		D1 = D1 ^ FO(D0, 6);
		// 7 round
		D0 = D0 ^ FO(D1, 7);
		// final
		D0 = FL(D0, 8);
		D1 = FL(D1, 9);

		BigEndianConversions.I2OSP(D1, output, outOff);
		BigEndianConversions.I2OSP(D0, output, outOff + 4);
	}

	/**
	 * This method decrypts a single block of data.
	 * 
	 * The array <code>in</code> must contain a whole block starting at
	 * <code>inOffset</code> and <code>out</code> must be large enough to hold
	 * an encrypted block starting at <code>outOffset</code>.
	 * 
	 * @param input
	 *            array of bytes containig the ciphertext to be decrypted
	 * @param inOff
	 *            index in array in, where the ciphertext block starts
	 * @param output
	 *            array of bytes which will contain the plaintext starting at
	 *            outOffset
	 * @param outOff
	 *            index in array out, where the plaintext block will start
	 */

	protected final void singleBlockDecrypt(byte[] input, int inOff,
			byte[] output, int outOff) {

		int D1 = BigEndianConversions.OS2IP(input, inOff);
		int D0 = BigEndianConversions.OS2IP(input, inOff + 4);

		D0 = FLINV(D0, 8);
		D1 = FLINV(D1, 9);
		D0 = D0 ^ FO(D1, 7);
		D1 = D1 ^ FO(D0, 6);
		D0 = FLINV(D0, 6);
		D1 = FLINV(D1, 7);
		D0 = D0 ^ FO(D1, 5);
		D1 = D1 ^ FO(D0, 4);
		D0 = FLINV(D0, 4);
		D1 = FLINV(D1, 5);
		D0 = D0 ^ FO(D1, 3);
		D1 = D1 ^ FO(D0, 2);
		D0 = FLINV(D0, 2);
		D1 = FLINV(D1, 3);
		D0 = D0 ^ FO(D1, 1);
		D1 = D1 ^ FO(D0, 0);
		D0 = FLINV(D0, 0);
		D1 = FLINV(D1, 1);

		BigEndianConversions.I2OSP(D0, output, outOff);
		BigEndianConversions.I2OSP(D1, output, outOff + 4);
	}

	// //////////////////////////////////////////////////////////////////////////////
	// MISTY1 PRIMITIVES
	// //////////////////////////////////////////////////////////////////////////////

	private int FI(int x, int key) {
		int xl9, xr7;

		xl9 = (x >>> 7) & 0x1ff;
		xr7 = x & 0x7f;
		xl9 = S9[xl9] ^ xr7;
		xr7 = S7[xr7] ^ ((xl9 ^ (key >>> 9)) & 0x7f);
		xl9 = xl9 ^ (key & 0x1ff);
		xl9 = S9[xl9] ^ xr7;

		return (xr7 << 9) | xl9;
	}

	private int FO(int x, int i) {
		int t0, t1;

		t0 = x >>> 16;
		t1 = x & 0xffff;
		t0 = t0 ^ keys[i];
		t0 = FI(t0, keys[((i + 5) & 7) + 8]);
		t0 = t0 ^ t1;
		t1 = t1 ^ keys[(i + 2) & 7];
		t1 = FI(t1, keys[((i + 1) & 7) + 8]);
		t1 = t1 ^ t0;
		t0 = t0 ^ keys[(i + 7) & 7];
		t0 = FI(t0, keys[((i + 3) & 7) + 8]);
		t0 = t0 ^ t1;
		t1 = t1 ^ keys[(i + 4) & 7];

		return (t1 << 16) | t0;
	}

	private int FL(int x, int i) {
		int d0, d1;

		d0 = x >>> 16;
		d1 = x & 0xffff;
		if ((i & 1) == 0) {
			d1 = d1 ^ (d0 & keys[i >> 1]);
			d0 = d0 ^ (d1 | keys[(((i >> 1) + 6) & 7) + 8]);
		} else {
			d1 = d1 ^ (d0 & keys[((((i - 1) >> 1) + 2) & 7) + 8]);
			d0 = d0 ^ (d1 | keys[(((i - 1) >> 1) + 4) & 7]);
		}

		return (d0 << 16) | d1;
	}

	private int FLINV(int x, int i) {
		int d0, d1;

		d0 = x >>> 16;
		d1 = x & 0xffff;
		if ((i & 1) == 0) {
			d0 = d0 ^ (d1 | keys[(((i >> 1) + 6) & 7) + 8]);
			d1 = d1 ^ (d0 & keys[i >> 1]);
		} else {
			d0 = d0 ^ (d1 | keys[(((i - 1) >> 1) + 4) & 7]);
			d1 = d1 ^ (d0 & keys[((((i - 1) >> 1) + 2) & 7) + 8]);
		}

		return (d0 << 16) | d1;
	}

}
