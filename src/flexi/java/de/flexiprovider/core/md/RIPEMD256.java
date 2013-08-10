/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group, Technische Universitaet
 * Darmstadt
 * 
 * For conditions of usage and distribution please refer to the file COPYING in
 * the root directory of this package.
 *
 * Created on Jul 26, 2005
 */
package de.flexiprovider.core.md;

import de.flexiprovider.common.util.LittleEndianConversions;

/**
 * This class implements the RIPEMD-256 message digest algorithm according to
 * the implementation guidelines found in <a
 * href="http://www.esat.kuleuven.ac.be/~bosselae/ripemd160.html#extensions"
 * >http://www.esat.kuleuven.ac.be/~bosselae/ripemd160.html#extensions</a>
 * <p>
 * Information concerning the RIPEMD message digest family can be found at <a
 * href
 * ="http://www.esat.kuleuven.ac.be/~bosselae/ripemd160.html">http://www.esat
 * .kuleuven.ac.be/~bosselae/ripemd160.html"></a>.
 * 
 * @author Elena Klintsevitch
 * @see RIPEMD160
 */
public final class RIPEMD256 extends MDFamilyDigest {

	/**
	 * The algorithm name.
	 */
	public static final String ALG_NAME = "RIPEMD256";

	/**
	 * The OID of RIPEMD256 (defined by Teletrust).
	 */
	public static final String OID = "1.3.36.3.2.3";

	// magic constants for initialization
	private static final int[] initState = { 0x67452301, 0xefcdab89,
			0x98badcfe, 0x10325476, 0x76543210, 0xfedcba98, 0x89abcdef,
			0x01234567 };

	// length of the resulting message digest in bytes (32*8=256)
	private static final int RIPEMD256_DIGEST_LENGTH = 32;

	// added constant
	private static final int[] KL = { 0x00000000, 0x5a827999, 0x6ed9eba1,
			0x8f1bbcdc }, // left
			KR = { 0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x00000000 }; // right

	// amount for shift left
	private static final int[][] SL = {
			{ 11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8 },
			{ 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12 },
			{ 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5 },
			{ 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12 } }, // left
			SR = { { 8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6 },
					{ 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11 },
					{ 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5 },
					{ 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8 } }; // right

	/**
	 * Constructor.
	 */
	public RIPEMD256() {
		super(RIPEMD256_DIGEST_LENGTH);
	}

	/**
	 * Resets the engine to its initial state.
	 */

	public void reset() {
		initMessageDigest(initState);
	}

	/**
	 * Computes the digest and resets the engine.
	 * 
	 * @return the digested message.
	 */
	public synchronized byte[] digest() {
		// produce the final digest
		byte[] digest = new byte[RIPEMD256_DIGEST_LENGTH];
		// padding because...
		padMessageDigest();

		// convert digest
		for (int i = 0; i < 8; i++) {
			LittleEndianConversions.I2OSP(state[i], digest, 4 * i);
		}

		// reset the engine to its initial state
		reset();
		return digest;
	}

	/**
	 * Processes a block of 64 bytes.
	 */
	protected synchronized void processBlock() {

		// aL - chaning variable A-E, aR- chaning variable A`-E`
		int[] aL = new int[4];
		int[] aR = new int[4];
		int t = 0;
		System.arraycopy(state, 0, aL, 0, 4);
		System.arraycopy(state, 4, aR, 0, 4);

		// i - namber of round
		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 16; j++) {
				// Left
				t = rotateLeft(aL[0] + F(i, aL[1], aL[2], aL[3])
						+ x[selWordL(i, j)] + KL[i], SL[i][j]);
				aL[0] = aL[3];
				aL[3] = aL[2];
				aL[2] = aL[1];
				aL[1] = t;
				// Right
				t = rotateLeft(aR[0] + F(3 - i, aR[1], aR[2], aR[3])
						+ x[selWordR(i, j)] + KR[i], SR[i][j]);
				aR[0] = aR[3];
				aR[3] = aR[2];
				aR[2] = aR[1];
				aR[1] = t;
			}

			t = aL[i];
			aL[i] = aR[i];
			aR[i] = t;
		}
		for (int k = 0; k < 4; k++) {
			state[k] = state[k] + aL[k];
			state[k + 4] = state[k + 4] + aR[k];
		}
	}

	/**
	 * basic conversion functions
	 */

	// selection of message word left
	private static int selWordL(int i, int j) {
		// table for permutation ro
		final int[] ro = { 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8 };
		if (i == 0) {
			return j;
		}
		int a = ro[j];
		for (int k = 1; k < i; k++) {
			a = ro[a];
		}
		return a;
	}

	// selection of message word right
	private static int selWordR(int i, int j) {
		int p = (9 * j + 5) & 0xf;
		return selWordL(i, p);
	}

	// nonlinear function for round i
	private static int F(int i, int u, int v, int w) {
		switch (i) {
		case 0:
			return u ^ v ^ w;
		case 1:
			return (u & v) | (~u & w);
		case 2:
			return (u | ~v) ^ w;
		case 3:
			return (u & w) | (v & ~w);
		default:
			return 0;
		}
	}

}
