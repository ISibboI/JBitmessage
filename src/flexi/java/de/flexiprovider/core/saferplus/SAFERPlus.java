/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.saferplus;

import de.flexiprovider.api.BlockCipher;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.keys.Key;
import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.api.keys.SecretKeySpec;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;

/**
 * This class provides the symmetric blockcipher SAFER+. It is used whithin the
 * JCE/JCA. The SAFER+ is a substitution/linear transformation cipher, wich
 * takes 16 bytes as input, processes it with a 128, 192 or 256 bit key and
 * calculates 16 bytes of output. The calculation is done during 8, 12 or 16
 * rounds with addition/subtraction in two additive groupes, namely addition
 * bytewise mod 256 and bitwise mod 2 (xor). A nonliner layer is provided by
 * exponentiation/logarithmation to the base 45 mod 257. Fast diffusion is
 * achieved by a linear transformation. This transformation is done by
 * multiplying the cipherblock with 16x16 invertible matrix.
 * 
 * @author Martin Strese
 * @author Marcus Lippert
 * @author Oliver Seiler
 */
public class SAFERPlus extends BlockCipher {

	/**
	 * The algorithm name.
	 */
	public static final String ALG_NAME = "SAFER+";

	private static final int blockSize = 16;

	private static final int[] firstSet = { 0, 3, 4, 7, 8, 11, 12, 15 }; //

	private static final int[] secondSet = { 1, 2, 5, 6, 9, 10, 13, 14 }; //

	private static int[] expTab = new int[257]; // table for fast expoentiation

	private static int[] logTab = new int[257]; // table for fast logarithmation

	private int[] actualBlock = new int[16]; // array containing the actual

	// processed block
	private int[] userKey; // used to keep the user key

	private int[] keyReg; // the keyregister used in the keyschedule

	private int[][] subKeys; // array of subkeys

	private int[] tmpBlock = new int[16]; // temporary array used during

	// matrixmultiplication

	private static int[][] bias = new int[33][16]; // bias values mask weak

	// keys

	private static int[][] matrixM = { // matrix for fast diffusion
	{ 2, 1, 1, 1, 4, 2, 1, 1, 2, 2, 4, 2, 4, 4, 16, 8 },
			{ 2, 1, 1, 1, 4, 2, 1, 1, 1, 1, 2, 1, 2, 2, 8, 4 },
			{ 1, 1, 4, 2, 2, 2, 4, 2, 16, 8, 4, 4, 2, 1, 1, 1 },
			{ 1, 1, 4, 2, 1, 1, 2, 1, 8, 4, 2, 2, 2, 1, 1, 1, },
			{ 16, 8, 2, 2, 4, 2, 4, 4, 1, 1, 4, 2, 1, 1, 2, 1 },
			{ 8, 4, 1, 1, 2, 1, 2, 2, 1, 1, 4, 2, 1, 1, 2, 1 },
			{ 2, 2, 4, 2, 4, 4, 16, 8, 2, 1, 1, 1, 4, 2, 1, 1 },
			{ 1, 1, 2, 1, 2, 2, 8, 4, 2, 1, 1, 1, 4, 2, 1, 1 },
			{ 4, 2, 4, 4, 16, 8, 2, 2, 1, 1, 2, 1, 1, 1, 4, 2 },
			{ 2, 1, 2, 2, 8, 4, 1, 1, 1, 1, 2, 1, 1, 1, 4, 2 },
			{ 4, 4, 16, 8, 1, 1, 2, 1, 4, 2, 1, 1, 4, 2, 2, 2 },
			{ 2, 2, 8, 4, 1, 1, 2, 1, 4, 2, 1, 1, 2, 1, 1, 1 },
			{ 1, 1, 2, 1, 1, 1, 4, 2, 4, 4, 16, 8, 2, 2, 4, 2 },
			{ 1, 1, 2, 1, 1, 1, 4, 2, 2, 2, 8, 4, 1, 1, 2, 1 },
			{ 4, 2, 1, 1, 2, 1, 1, 1, 4, 2, 2, 2, 16, 8, 4, 4 },
			{ 4, 2, 1, 1, 2, 1, 1, 1, 2, 1, 1, 1, 8, 4, 2, 2 } };

	private static int[][] matrixInvM = { // the inverse matrix M
	{ 2, -4, 1, -2, 1, -1, 2, -2, 1, -1, 1, -1, 4, -8, 1, -2 },
			{ -2, 4, -2, 4, -1, 1, -4, 4, -1, 1, -2, 2, -8, 16, -1, 2 },
			{ 1, -2, 1, -2, 2, -2, 1, -1, 1, -1, 1, -1, 2, -4, 4, -8 },
			{ -2, 4, -1, 2, -4, 4, -1, 1, -2, 2, -1, 1, -2, 4, -8, 16 },
			{ 1, -2, 2, -2, 1, -1, 1, -1, 1, -1, 4, -8, 1, -2, 2, -4 },
			{ -1, 2, -4, 4, -1, 1, -2, 2, -1, 1, -8, 16, -2, 4, -2, 4 },
			{ 4, -8, 1, -1, 1, -1, 1, -1, 2, -2, 2, -4, 1, -2, 1, -2 },
			{ -8, 16, -1, 1, -2, 2, -1, 1, -4, 4, -2, 4, -1, 2, -2, 4 },
			{ 2, -2, 1, -1, 1, -2, 2, -4, 4, -8, 1, -2, 1, -1, 1, -1 },
			{ -4, 4, -1, 1, -2, 4, -2, 4, -8, 16, -1, 2, -2, 2, -1, 1 },
			{ 1, -1, 1, -1, 1, -2, 4, -8, 2, -4, 1, -2, 1, -1, 2, -2 },
			{ -1, 1, -2, 2, -1, 2, -8, 16, -2, 4, -2, 4, -1, 1, -4, 4 },
			{ 1, -1, 2, -4, 4, -8, 1, -2, 1, -2, 1, -1, 2, -2, 1, -1 },
			{ -2, 2, -2, 4, -8, 16, -1, 2, -2, 4, -1, 1, -4, 4, -1, 1 },
			{ 1, -1, 4, -8, 2, -4, 1, -2, 1, -2, 2, -2, 1, -1, 1, -1 },
			{ -1, 1, -8, 16, -2, 4, -2, 4, -1, 2, -4, 4, -1, 1, -2, 2 }, };

	/**
	 * This is the default constructor. It initializes the tables needed during
	 * en- and decryption, i.e. exponentiation, logarithmation and bias values.
	 */
	public SAFERPlus() {
		makeExpTab();
		makeLogTab();
		fillBias();
	}

	/**
	 * @return the name of this cipher
	 */
	public String getName() {
		return ALG_NAME;
	}

	/**
	 * Returns the key size of the given key object. Checks whether the key
	 * object is an instance of <tt>SAFERPlusKey</tt> or <tt>SecretKeySpec</tt>
	 * and whether the key size is within the specified range for SAFER+. 128,
	 * 192 and 256 bit keys are allowed.
	 * 
	 * @param key
	 *            the key object
	 * @return the key size of the given key object.
	 * @throws InvalidKeyException
	 *             if key is invalid.
	 */
	public int getKeySize(Key key) throws InvalidKeyException {

		if (!((key instanceof SAFERPlusKey) || (key instanceof SecretKeySpec))) {
			throw new InvalidKeyException("not a SAFER+ key.");
		}

		int keyLen = key.getEncoded().length;

		if (keyLen != 16 && keyLen != 24 && keyLen != 32) {
			throw new InvalidKeyException("key size not valid for SAFER+.");
		}

		return keyLen << 3;
	}

	/**
	 * This method returns the blocksize, the algorithm uses. This method will
	 * normaly be called by the padding scheme. It must be assured, that this
	 * method is exclusivly called, when the algorithm is either in encryption
	 * or in decryption mode. The blocksize in SAFERPlus is always 16 bytes.
	 * 
	 * @return the used blocksize
	 */
	public int getCipherBlockSize() {
		return blockSize; // The blocksize is always 16 bytes
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
	 *             if the given key is inappropriate for initialising this
	 *             cipher.
	 */
	protected void initCipherEncrypt(SecretKey key,
			AlgorithmParameterSpec params) throws InvalidKeyException {
		if (!(key instanceof SAFERPlusKey)) {
			throw new InvalidKeyException("not a SAFER+ key.");
		}

		byte[] tmpArray = key.getEncoded(); // get key as a byte array,
		userKey = new int[tmpArray.length]; // alloc memory,
		for (int i = 0; i < tmpArray.length; i++) { // copy it into an int array
			userKey[i] = (tmpArray[i] + 256) & 0xff;
		}
		createSubKeys(userKey.length + 1); // and produce subkeys
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
	 *             if the given key is inappropriate for initialising this
	 *             cipher.
	 */
	protected void initCipherDecrypt(SecretKey key,
			AlgorithmParameterSpec params) throws InvalidKeyException {
		initCipherEncrypt(key, params);
	}

	/**
	 * This method encrypts a single block of data, and may only be called, when
	 * the block cipher is in encrytion mode, what the surrounding framework has
	 * to asure. It has to be assured, too, that the array <TT>in</TT> contains
	 * a whole block starting at <TT>inOffset</TT> and that <TT>out</TT> is
	 * large enough to hold an encrypted block starting at <TT>outOffset</TT>
	 * 
	 * @param in
	 *            array of bytes which contains the plaintext to be encrypted
	 * @param inOffset
	 *            index in array in, where the plaintext block starts
	 * @param out
	 *            array of bytes which will contain the ciphertext
	 * @param outOffset
	 *            index in array out, where the ciphertext block will start
	 */
	protected void singleBlockEncrypt(byte[] in, int inOffset, byte[] out,
			int outOffset) {

		int maxRounds; // number of rounds during encryption
		int round = 1; // the actual round
		maxRounds = (userKey.length) >> 1;

		// fetch the block, ...
		for (int i = 0; i < 16; i++) {
			actualBlock[i] = (in[inOffset + i]) & 255; // Extend byte to int
			// without signe extension
		}

		// ... encrypt it during n(maxRounds) rounds, ...
		while (round <= maxRounds) {
			mod2Trans(firstSet, (round << 1) - 2); // add 1.subkey) mod 256
			mod256Add(secondSet, (round << 1) - 2); // add 1. subkey bitwise mod
			// 2
			powerTrans(firstSet); // non-linear step
			logTrans(secondSet);
			mod256Add(firstSet, (round << 1) - 1); // add 2. subkey mod 256
			mod2Trans(secondSet, (round << 1) - 1); // add 2. subkey bitwise mod
			// 2
			matrixTrans();
			round++; // next round
		}

		// ... aply the output transformation ...
		mod2Trans(firstSet, maxRounds << 1);
		mod256Add(secondSet, maxRounds << 1);

		// ... and write it back.
		for (int i = 0; i < 16; i++) {
			out[outOffset + i] = (byte) actualBlock[i];
		}
	}

	/**
	 * This method decrypts a single block of data, and may only be called, when
	 * the block cipher is in decrytion mode. It has to be asured, too, that the
	 * array <TT>in</TT> contains a whole block starting at <TT>inOffset</TT>
	 * and that <TT>out</TT> is large enogh to hold an decrypted block starting
	 * at <TT>outOffset</TT>
	 * 
	 * @param in
	 *            array of bytes which contains the ciphertext to be decrypted
	 * @param inOffset
	 *            index in array in, where the ciphertext block starts
	 * @param out
	 *            array of bytes which will contain the plaintext starting at
	 *            outOffset
	 * @param outOffset
	 *            index in array out, where the plaintext block will start
	 */
	protected void singleBlockDecrypt(byte[] in, int inOffset, byte[] out,
			int outOffset) {
		int maxRounds; // number of rounds during decryption
		int round = 1; // the actual round
		actualBlock = new int[16];
		maxRounds = userKey.length >> 1;

		// fetch the block, ...
		for (int i = 0; i < 16; i++) {
			actualBlock[i] = in[inOffset + i] & 255;
		}

		// ... revert the output transformation, ...
		mod2Trans(firstSet, maxRounds << 1);
		mod256Sub(secondSet, maxRounds << 1);

		// ... undo enryption rounds ...
		while (round <= maxRounds) {
			invMatrixTrans(); // undo trans-
			mod256Sub(firstSet, ((maxRounds - round) << 1) + 1); // formations
			mod2Trans(secondSet, ((maxRounds - round) << 1) + 1); // made
			// during
			logTrans(firstSet); // encryption
			powerTrans(secondSet);
			mod2Trans(firstSet, (maxRounds - round) << 1);
			mod256Sub(secondSet, (maxRounds - round) << 1);
			round++;
		}

		// and finally store the decrypted block
		for (int i = 0; i < 16; i++) {
			out[outOffset + i] = (byte) actualBlock[i];
		}
	}

	/***************************************************************************
	 * the private methods used internally *
	 **************************************************************************/

	/**
	 * This method fills the array expTab. The array-cell i contains the value
	 * 45^i (mod 257) and the cell 128 contains the value 0 due to a convention.
	 * This array is supported to speed up exponentiation.
	 */
	private void makeExpTab() {
		expTab[0] = 1;
		for (int i = 1; i < 256; i++) {
			expTab[i] = (45 * expTab[i - 1]) % 257;
		}
		// this is a convention from the script (we need values between 0 and
		// 255)
		expTab[128] = 0;
	}

	/**
	 * This fills the array logTab to evaluate logarithms more quickly. The
	 * values are calculated from those in the array expTab.
	 */
	private void makeLogTab() {
		for (int i = 0; i < 256; i++) {
			logTab[expTab[i]] = i; // compute the inverse of expTab
		}
	}

	/**
	 * This method sets up the table which stores the bias-values used for the
	 * key schedule. These values are calculated via successive exponentiation
	 * of 45^x (mod 257), where x= 17i + j (i is the row- and j the column
	 * counter of the 2D-array). The exponentiation is done be reading the array
	 * expTab.
	 */
	private void fillBias() {
		int i, j;

		// bias value for the first 16 subkeys.
		for (i = 2; i <= 17; i++) {
			// Processing according to script pp. 8
			for (j = 1; j <= 16; j++) {
				bias[i - 1][j - 1] = expTab[expTab[(17 * i + j) & 255]];
			}
		}

		// bias value for the last 16 subkeys.
		for (i = 18; i <= 33; i++) {
			for (j = 1; j <= 16; j++) {
				bias[i - 1][j - 1] = expTab[(17 * i + j) & 255];
			}
		}
	}

	/**
	 * This method generates the round subkeys (key schedule).
	 * 
	 * @param length
	 *            the number of subkeys which will be needed (equivalent to the
	 *            keylength in bytes + 1)
	 */
	private void createSubKeys(int length) {
		keyReg = new int[length]; // transform. are made whithin a keyregister
		subKeys = new int[length][16]; // array containig the subkeys
		int parity = 0; // the keyregister contains key-length + 1
		// bytes and this extra byte contains the
		// bitwise sum as a parity-byte

		for (int i = 0; i < 16; i++) {
			subKeys[0][i] = userKey[i]; // the first subkey is the userkey
		}
		for (int i = 0; i < length - 1; i++) {
			keyReg[i] = userKey[i]; // fill the keyregister initially with
			// the userkey
			parity ^= userKey[i]; // and calculate the parity
			// (bitwise summation/xor).
		}
		keyReg[length - 1] = parity; // Store the parity in the extra byte
		bitRotate(length); // and rotate the bits
		for (int j = 1; j < length; j++) { // for the subkey j start at col j,
			for (int i = 0; i < 16; i++) { // take 16 bytes (wrap around at the
				// end
				// of the keyregister if nescessary),
				subKeys[j][i] = (bias[j][i] + keyReg[(j + i) % length]) & 0xff; // add
				// bias
			}
			bitRotate(length); // and rotate
		}
	}

	/**
	 * This method rotates the first l bytes in the keyReg 3 Bits to the left
	 * 
	 * @param l
	 *            The number of bytes, which will be rotated
	 */
	private void bitRotate(int l) {
		int lowByte;
		int highMask = 0x700; // 00000111.00000000

		for (int i = 0; i < l; i++) { // process l bytes
			keyReg[i] <<= 3; // leftshift 3 bits
			lowByte = (highMask & keyReg[i]) >>> 8; // move the 3 leftmost bits
			keyReg[i] = (lowByte | keyReg[i]) & 255; // and xor the result
		}
	}

	/**
	 * This method adds the bytes of the actually processed block selected by
	 * the etries of indexSet to the corresponding bytes of the actual subkey
	 * (bitwise mod 2).
	 * 
	 * @param indexSet
	 *            array containing the indexes of the bytes which shall be
	 *            changed.
	 * @param keyNum
	 *            number of the actual subkey
	 */
	private void mod2Trans(int[] indexSet, int keyNum) {
		for (int i = 0; i < 8; i++) {
			actualBlock[indexSet[i]] ^= subKeys[keyNum][indexSet[i]];
		}
	}

	/**
	 * This method adds the bytes of the actually processed block selected by
	 * the etries of indexSet to the corresponding bytes of the actual subkey
	 * (bytewise mod 256).
	 * 
	 * @param indexSet
	 *            array containing the indexes of the bytes which shall be
	 *            changed.
	 * @param keyNum
	 *            number of the actual subkey
	 */
	private void mod256Add(int[] indexSet, int keyNum) {

		for (int i = 0; i < 8; i++) {
			actualBlock[indexSet[i]] = actualBlock[indexSet[i]]
					+ subKeys[keyNum][indexSet[i]] & 255;
		}

	}

	/**
	 * This method subtracts from the bytes of the actually processed block
	 * selected by the etries of indexSet the corresponding bytes of the actual
	 * subkey (bytewise mod 256).
	 * 
	 * @param indexSet
	 *            array containing the indexes of the bytes which shall be
	 *            changed.
	 * @param keyNum
	 *            number of the actual subkey
	 */
	private void mod256Sub(int[] indexSet, int keyNum) {

		for (int i = 0; i < 8; i++) {
			actualBlock[indexSet[i]] = actualBlock[indexSet[i]]
					- subKeys[keyNum][indexSet[i]] & 255;
		}
	}

	/**
	 * This methods computes for the bytes x selected by set 46^x mod 257 by
	 * looking up the results in expTab[].
	 * 
	 * @param set
	 *            array containing the indexes of the bytes which shall be
	 *            changed.
	 */
	private void powerTrans(int[] set) {

		for (int i = 0; i < 8; i++) {
			actualBlock[set[i]] = expTab[actualBlock[set[i]]];
		}
	}

	/**
	 * This methods computes for the bytes x selected by set log_45 x mod 257 by
	 * looking up the valuse in logTab[].
	 * 
	 * @param set
	 *            array containing the indexes of the bytes which shall be
	 *            changed.
	 */
	private void logTrans(int[] set) {

		for (int i = 0; i < 8; i++) {
			actualBlock[set[i]] = logTab[actualBlock[set[i]]];
		}
	}

	/**
	 * This method executes the output transformation of a round by multiplying
	 * the actual block with the transformation matrix.
	 */
	private void invMatrixTrans() {
		int i, j;

		for (i = 0; i < 16; i++) {
			tmpBlock[i] = 0;
			for (j = 0; j < 16; j++) {
				tmpBlock[i] += matrixInvM[i][j] * actualBlock[j]; // worst
				// case:
				// 256*256*16
				// does not
				// exceed capacity of int
			}
			tmpBlock[i] &= 255; // so we calculate modulo at the end
		}

		for (i = 0; i < 16; i++) { // store the result
			actualBlock[i] = tmpBlock[i];
		}
	}

	/**
	 * This method reverts the output transformation of an encryption round by
	 * multiplying the actual block with the inverse of the transformation
	 * matrix.
	 */
	private void matrixTrans() {
		int i, j;

		for (i = 0; i < 16; i++) {
			tmpBlock[i] = 0;
			for (j = 0; j < 16; j++) {
				tmpBlock[i] += matrixM[i][j] * actualBlock[j]; // worst
				// case:
				// 256*256*16
				// does not
				// exceed capacity of int
			}
			tmpBlock[i] &= 255; // so we calculate modulo at the end
		}
		for (i = 0; i < 16; i++) { // store the result
			actualBlock[i] = tmpBlock[i];
		}
	}

}
