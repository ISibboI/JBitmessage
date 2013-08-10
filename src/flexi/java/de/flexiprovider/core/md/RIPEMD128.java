/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 */
package de.flexiprovider.core.md;

import de.flexiprovider.common.util.LittleEndianConversions;

/**
 * This class implements the RIPEMD-128 message digest algorithm according to
 * the Handbook of Applied Cryptography, Menezes, van Oorschot, Vanstone, CRC
 * Press, 19??, algorithm 9.55
 * 
 * <p>
 * The algorithm has been invented by Hans Dobbertin, and further information
 * concerning the RIPEMD message digest family can be found at <a
 * href="http://www.esat.kuleuven.ac.be/~bosselae/ripemd160.html">
 * www.esat.kuleuven.ac.be/~bosselae/ripemd160.html</a>.
 * 
 * <p>
 * The efficiency of this implementation has been tested on a AMD K6-III, 450
 * MHz, running Windows 98 SE, using jdk 1.2.2. The hashing rate is about 55
 * MBits / second.
 * 
 * @author Oliver Seiler
 */
public final class RIPEMD128 extends MDFamilyDigest {

	/**
	 * The algorithm name.
	 */
	public static final String ALG_NAME = "RIPEMD128";

	/**
	 * The OID of RIPEMD128 (defined by Teletrust).
	 */
	public static final String OID = "1.3.36.3.2.2";

	// magic constants for initialization
	private static final int[] initState = { 0x67452301, 0xefcdab89,
			0x98badcfe, 0x10325476 };

	// length of the resulting message digest in bytes
	private static final int RIPEMD128_DIGEST_LENGTH = 16;

	private static final int[]

	// word access order
			Zl = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4,
					13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8, 3, 10, 14,
					4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0,
					8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2 },
			Zr = { 5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11,
					3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2, 15, 5, 1, 3,
					7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11,
					15, 0, 5, 12, 2, 13, 9, 7, 10, 14 },
			// rotations
			Sl = { 11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7,
					6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12, 11,
					13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12,
					14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12 }, Sr = { 8,
					9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13,
					15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11, 9, 7, 15,
					11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11,
					14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8 };

	/**
	 * Constructor.
	 */
	public RIPEMD128() {
		super(RIPEMD128_DIGEST_LENGTH);
	}

	/**
	 * reset the engine to its initial state
	 */
	public void reset() {
		initMessageDigest(initState);
	}

	/**
	 * compute the digest and reset the engine
	 * 
	 * @return the message digest in a byte array
	 */
	public synchronized byte[] digest() {
		// produce the final digest
		byte[] digest = new byte[RIPEMD128_DIGEST_LENGTH];

		padMessageDigest();

		// convert digest
		LittleEndianConversions.I2OSP(state[0], digest, 0);
		LittleEndianConversions.I2OSP(state[1], digest, 4);
		LittleEndianConversions.I2OSP(state[2], digest, 8);
		LittleEndianConversions.I2OSP(state[3], digest, 12);

		// reset the engine to its initial state
		reset();

		return digest;
	}

	/**
	 * process a block of 64 bytes
	 */
	protected synchronized void processBlock() {
		int Al = state[0];
		int Bl = state[1];
		int Cl = state[2];
		int Dl = state[3];

		int Ar = state[0];
		int Br = state[1];
		int Cr = state[2];
		int Dr = state[3];

		int t = 0;
		int j = 0;

		// Round 1
		for (j = 0; j < 16; j++) {

			// Left
			t = Al + F(Bl, Cl, Dl) + x[Zl[j]];
			Al = Dl;
			Dl = Cl;
			Cl = Bl;
			Bl = rotateLeft(t, Sl[j]);

			// Right
			t = Ar + K(Br, Cr, Dr) + x[Zr[j]] + 0x50a28be6;
			Ar = Dr;
			Dr = Cr;
			Cr = Br;
			Br = rotateLeft(t, Sr[j]);
		}

		// Round 2
		for (j = 16; j < 32; j++) {

			// Left
			t = Al + G(Bl, Cl, Dl) + x[Zl[j]] + 0x5a827999;
			Al = Dl;
			Dl = Cl;
			Cl = Bl;
			Bl = rotateLeft(t, Sl[j]);

			// Right
			t = Ar + H(Br, Cr, Dr) + x[Zr[j]] + 0x5c4dd124;
			Ar = Dr;
			Dr = Cr;
			Cr = Br;
			Br = rotateLeft(t, Sr[j]);
		}

		// Round 3
		for (j = 32; j < 48; j++) {

			// Left
			t = Al + H(Bl, Cl, Dl) + x[Zl[j]] + 0x6ed9eba1;
			Al = Dl;
			Dl = Cl;
			Cl = Bl;
			Bl = rotateLeft(t, Sl[j]);

			// Right
			t = Ar + G(Br, Cr, Dr) + x[Zr[j]] + 0x6d703ef3;
			Ar = Dr;
			Dr = Cr;
			Cr = Br;
			Br = rotateLeft(t, Sr[j]);
		}

		// Round 4
		for (j = 48; j < 64; j++) {

			// Left
			t = Al + K(Bl, Cl, Dl) + x[Zl[j]] + 0x8f1bbcdc;
			Al = Dl;
			Dl = Cl;
			Cl = Bl;
			Bl = rotateLeft(t, Sl[j]);

			// Right
			t = Ar + F(Br, Cr, Dr) + x[Zr[j]];
			Ar = Dr;
			Dr = Cr;
			Cr = Br;
			Br = rotateLeft(t, Sr[j]);
		}

		Cl += state[1] + Dr;
		state[1] = state[2] + Dl + Ar;
		state[2] = state[3] + Al + Br;
		state[3] = state[0] + Bl + Cr;
		state[0] = Cl;
	}

	/* basic conversion functions */

	private static int F(int u, int v, int w) {
		return u ^ v ^ w;
	}

	private static int G(int u, int v, int w) {
		return (u & v) | (~u & w);
	}

	private static int H(int u, int v, int w) {
		return (u | ~v) ^ w;
	}

	private static int K(int u, int v, int w) {
		return (u & w) | (v & ~w);
	}

}
