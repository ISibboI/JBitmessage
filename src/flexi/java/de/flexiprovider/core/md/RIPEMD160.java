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
 * This class implements the RIPEMD-160 message digest algorithm according to
 * the Handbook of Applied Cryptography, Menezes, van Oorschot, Vanstone, CRC
 * Press, 1997, algorithm 9.55
 * 
 * <p>
 * The algorithm has been invented by Hans Dobbertin, and further information
 * concerning the RIPEMD message digest family can be found at <a
 * href="http://www.esat.kuleuven.ac.be/~bosselae/ripemd160.html">
 * www.esat.kuleuven.ac.be/~bosselae/ripemd160.html</a>.
 * 
 * <p>
 * The efficiency of this implementation has been tested on a AMD K6-III, 450
 * MHz, running Windows 98 SE, using jdk 1.2.2. The hashing rate is about 38
 * MBits / second.
 * 
 * @author Oliver Seiler
 */
public final class RIPEMD160 extends MDFamilyDigest {

	/**
	 * The algorithm name.
	 */
	public static final String ALG_NAME = "RIPEMD160";

	/**
	 * The OID of RIPEMD160 (defined by Teletrust).
	 */
	public static final String OID = "1.3.36.3.2.1";

	// magic constants for initialization
	private static final int[] initState = { 0x67452301, 0xefcdab89,
			0x98badcfe, 0x10325476, 0xc3d2e1f0 };

	// length of the resulting message digest in bytes
	private static final int RIPEMD160_DIGEST_LENGTH = 20;

	/**
	 * Constructor.
	 */
	public RIPEMD160() {
		super(RIPEMD160_DIGEST_LENGTH);
	}

	/**
	 * reset the engine to its initial state
	 */
	public void reset() {
		initMessageDigest(initState);
	}

	/**
	 * Compute the digest and reset the engine
	 * 
	 * @return the message digest in a byte array
	 */
	public synchronized byte[] digest() {
		// produce the final digest
		byte[] digest = new byte[RIPEMD160_DIGEST_LENGTH];

		padMessageDigest();

		// convert digest
		LittleEndianConversions.I2OSP(state[0], digest, 0);
		LittleEndianConversions.I2OSP(state[1], digest, 4);
		LittleEndianConversions.I2OSP(state[2], digest, 8);
		LittleEndianConversions.I2OSP(state[3], digest, 12);
		LittleEndianConversions.I2OSP(state[4], digest, 16);

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
		int El = state[4];

		int Ar = state[0];
		int Br = state[1];
		int Cr = state[2];
		int Dr = state[3];
		int Er = state[4];

		// rounds 0-15 (left)
		Al = rotateLeft(Al + F(Bl, Cl, Dl) + x[0], 11) + El;
		Cl = rotateLeft(Cl, 10);
		El = rotateLeft(El + F(Al, Bl, Cl) + x[1], 14) + Dl;
		Bl = rotateLeft(Bl, 10);
		Dl = rotateLeft(Dl + F(El, Al, Bl) + x[2], 15) + Cl;
		Al = rotateLeft(Al, 10);
		Cl = rotateLeft(Cl + F(Dl, El, Al) + x[3], 12) + Bl;
		El = rotateLeft(El, 10);
		Bl = rotateLeft(Bl + F(Cl, Dl, El) + x[4], 5) + Al;
		Dl = rotateLeft(Dl, 10);
		Al = rotateLeft(Al + F(Bl, Cl, Dl) + x[5], 8) + El;
		Cl = rotateLeft(Cl, 10);
		El = rotateLeft(El + F(Al, Bl, Cl) + x[6], 7) + Dl;
		Bl = rotateLeft(Bl, 10);
		Dl = rotateLeft(Dl + F(El, Al, Bl) + x[7], 9) + Cl;
		Al = rotateLeft(Al, 10);
		Cl = rotateLeft(Cl + F(Dl, El, Al) + x[8], 11) + Bl;
		El = rotateLeft(El, 10);
		Bl = rotateLeft(Bl + F(Cl, Dl, El) + x[9], 13) + Al;
		Dl = rotateLeft(Dl, 10);
		Al = rotateLeft(Al + F(Bl, Cl, Dl) + x[10], 14) + El;
		Cl = rotateLeft(Cl, 10);
		El = rotateLeft(El + F(Al, Bl, Cl) + x[11], 15) + Dl;
		Bl = rotateLeft(Bl, 10);
		Dl = rotateLeft(Dl + F(El, Al, Bl) + x[12], 6) + Cl;
		Al = rotateLeft(Al, 10);
		Cl = rotateLeft(Cl + F(Dl, El, Al) + x[13], 7) + Bl;
		El = rotateLeft(El, 10);
		Bl = rotateLeft(Bl + F(Cl, Dl, El) + x[14], 9) + Al;
		Dl = rotateLeft(Dl, 10);
		Al = rotateLeft(Al + F(Bl, Cl, Dl) + x[15], 8) + El;
		Cl = rotateLeft(Cl, 10);

		// rounds 0-15 (right)
		Ar = rotateLeft(Ar + L(Br, Cr, Dr) + x[5] + 0x50a28be6, 8) + Er;
		Cr = rotateLeft(Cr, 10);
		Er = rotateLeft(Er + L(Ar, Br, Cr) + x[14] + 0x50a28be6, 9) + Dr;
		Br = rotateLeft(Br, 10);
		Dr = rotateLeft(Dr + L(Er, Ar, Br) + x[7] + 0x50a28be6, 9) + Cr;
		Ar = rotateLeft(Ar, 10);
		Cr = rotateLeft(Cr + L(Dr, Er, Ar) + x[0] + 0x50a28be6, 11) + Br;
		Er = rotateLeft(Er, 10);
		Br = rotateLeft(Br + L(Cr, Dr, Er) + x[9] + 0x50a28be6, 13) + Ar;
		Dr = rotateLeft(Dr, 10);
		Ar = rotateLeft(Ar + L(Br, Cr, Dr) + x[2] + 0x50a28be6, 15) + Er;
		Cr = rotateLeft(Cr, 10);
		Er = rotateLeft(Er + L(Ar, Br, Cr) + x[11] + 0x50a28be6, 15) + Dr;
		Br = rotateLeft(Br, 10);
		Dr = rotateLeft(Dr + L(Er, Ar, Br) + x[4] + 0x50a28be6, 5) + Cr;
		Ar = rotateLeft(Ar, 10);
		Cr = rotateLeft(Cr + L(Dr, Er, Ar) + x[13] + 0x50a28be6, 7) + Br;
		Er = rotateLeft(Er, 10);
		Br = rotateLeft(Br + L(Cr, Dr, Er) + x[6] + 0x50a28be6, 7) + Ar;
		Dr = rotateLeft(Dr, 10);
		Ar = rotateLeft(Ar + L(Br, Cr, Dr) + x[15] + 0x50a28be6, 8) + Er;
		Cr = rotateLeft(Cr, 10);
		Er = rotateLeft(Er + L(Ar, Br, Cr) + x[8] + 0x50a28be6, 11) + Dr;
		Br = rotateLeft(Br, 10);
		Dr = rotateLeft(Dr + L(Er, Ar, Br) + x[1] + 0x50a28be6, 14) + Cr;
		Ar = rotateLeft(Ar, 10);
		Cr = rotateLeft(Cr + L(Dr, Er, Ar) + x[10] + 0x50a28be6, 14) + Br;
		Er = rotateLeft(Er, 10);
		Br = rotateLeft(Br + L(Cr, Dr, Er) + x[3] + 0x50a28be6, 12) + Ar;
		Dr = rotateLeft(Dr, 10);
		Ar = rotateLeft(Ar + L(Br, Cr, Dr) + x[12] + 0x50a28be6, 6) + Er;
		Cr = rotateLeft(Cr, 10);

		// rounds 16-31 (left)
		El = rotateLeft(El + G(Al, Bl, Cl) + x[7] + 0x5a827999, 7) + Dl;
		Bl = rotateLeft(Bl, 10);
		Dl = rotateLeft(Dl + G(El, Al, Bl) + x[4] + 0x5a827999, 6) + Cl;
		Al = rotateLeft(Al, 10);
		Cl = rotateLeft(Cl + G(Dl, El, Al) + x[13] + 0x5a827999, 8) + Bl;
		El = rotateLeft(El, 10);
		Bl = rotateLeft(Bl + G(Cl, Dl, El) + x[1] + 0x5a827999, 13) + Al;
		Dl = rotateLeft(Dl, 10);
		Al = rotateLeft(Al + G(Bl, Cl, Dl) + x[10] + 0x5a827999, 11) + El;
		Cl = rotateLeft(Cl, 10);
		El = rotateLeft(El + G(Al, Bl, Cl) + x[6] + 0x5a827999, 9) + Dl;
		Bl = rotateLeft(Bl, 10);
		Dl = rotateLeft(Dl + G(El, Al, Bl) + x[15] + 0x5a827999, 7) + Cl;
		Al = rotateLeft(Al, 10);
		Cl = rotateLeft(Cl + G(Dl, El, Al) + x[3] + 0x5a827999, 15) + Bl;
		El = rotateLeft(El, 10);
		Bl = rotateLeft(Bl + G(Cl, Dl, El) + x[12] + 0x5a827999, 7) + Al;
		Dl = rotateLeft(Dl, 10);
		Al = rotateLeft(Al + G(Bl, Cl, Dl) + x[0] + 0x5a827999, 12) + El;
		Cl = rotateLeft(Cl, 10);
		El = rotateLeft(El + G(Al, Bl, Cl) + x[9] + 0x5a827999, 15) + Dl;
		Bl = rotateLeft(Bl, 10);
		Dl = rotateLeft(Dl + G(El, Al, Bl) + x[5] + 0x5a827999, 9) + Cl;
		Al = rotateLeft(Al, 10);
		Cl = rotateLeft(Cl + G(Dl, El, Al) + x[2] + 0x5a827999, 11) + Bl;
		El = rotateLeft(El, 10);
		Bl = rotateLeft(Bl + G(Cl, Dl, El) + x[14] + 0x5a827999, 7) + Al;
		Dl = rotateLeft(Dl, 10);
		Al = rotateLeft(Al + G(Bl, Cl, Dl) + x[11] + 0x5a827999, 13) + El;
		Cl = rotateLeft(Cl, 10);
		El = rotateLeft(El + G(Al, Bl, Cl) + x[8] + 0x5a827999, 12) + Dl;
		Bl = rotateLeft(Bl, 10);

		// rounds 16-31 (right)
		Er = rotateLeft(Er + K(Ar, Br, Cr) + x[6] + 0x5c4dd124, 9) + Dr;
		Br = rotateLeft(Br, 10);
		Dr = rotateLeft(Dr + K(Er, Ar, Br) + x[11] + 0x5c4dd124, 13) + Cr;
		Ar = rotateLeft(Ar, 10);
		Cr = rotateLeft(Cr + K(Dr, Er, Ar) + x[3] + 0x5c4dd124, 15) + Br;
		Er = rotateLeft(Er, 10);
		Br = rotateLeft(Br + K(Cr, Dr, Er) + x[7] + 0x5c4dd124, 7) + Ar;
		Dr = rotateLeft(Dr, 10);
		Ar = rotateLeft(Ar + K(Br, Cr, Dr) + x[0] + 0x5c4dd124, 12) + Er;
		Cr = rotateLeft(Cr, 10);
		Er = rotateLeft(Er + K(Ar, Br, Cr) + x[13] + 0x5c4dd124, 8) + Dr;
		Br = rotateLeft(Br, 10);
		Dr = rotateLeft(Dr + K(Er, Ar, Br) + x[5] + 0x5c4dd124, 9) + Cr;
		Ar = rotateLeft(Ar, 10);
		Cr = rotateLeft(Cr + K(Dr, Er, Ar) + x[10] + 0x5c4dd124, 11) + Br;
		Er = rotateLeft(Er, 10);
		Br = rotateLeft(Br + K(Cr, Dr, Er) + x[14] + 0x5c4dd124, 7) + Ar;
		Dr = rotateLeft(Dr, 10);
		Ar = rotateLeft(Ar + K(Br, Cr, Dr) + x[15] + 0x5c4dd124, 7) + Er;
		Cr = rotateLeft(Cr, 10);
		Er = rotateLeft(Er + K(Ar, Br, Cr) + x[8] + 0x5c4dd124, 12) + Dr;
		Br = rotateLeft(Br, 10);
		Dr = rotateLeft(Dr + K(Er, Ar, Br) + x[12] + 0x5c4dd124, 7) + Cr;
		Ar = rotateLeft(Ar, 10);
		Cr = rotateLeft(Cr + K(Dr, Er, Ar) + x[4] + 0x5c4dd124, 6) + Br;
		Er = rotateLeft(Er, 10);
		Br = rotateLeft(Br + K(Cr, Dr, Er) + x[9] + 0x5c4dd124, 15) + Ar;
		Dr = rotateLeft(Dr, 10);
		Ar = rotateLeft(Ar + K(Br, Cr, Dr) + x[1] + 0x5c4dd124, 13) + Er;
		Cr = rotateLeft(Cr, 10);
		Er = rotateLeft(Er + K(Ar, Br, Cr) + x[2] + 0x5c4dd124, 11) + Dr;
		Br = rotateLeft(Br, 10);

		// rounds 32-47 (left)
		Dl = rotateLeft(Dl + H(El, Al, Bl) + x[3] + 0x6ed9eba1, 11) + Cl;
		Al = rotateLeft(Al, 10);
		Cl = rotateLeft(Cl + H(Dl, El, Al) + x[10] + 0x6ed9eba1, 13) + Bl;
		El = rotateLeft(El, 10);
		Bl = rotateLeft(Bl + H(Cl, Dl, El) + x[14] + 0x6ed9eba1, 6) + Al;
		Dl = rotateLeft(Dl, 10);
		Al = rotateLeft(Al + H(Bl, Cl, Dl) + x[4] + 0x6ed9eba1, 7) + El;
		Cl = rotateLeft(Cl, 10);
		El = rotateLeft(El + H(Al, Bl, Cl) + x[9] + 0x6ed9eba1, 14) + Dl;
		Bl = rotateLeft(Bl, 10);
		Dl = rotateLeft(Dl + H(El, Al, Bl) + x[15] + 0x6ed9eba1, 9) + Cl;
		Al = rotateLeft(Al, 10);
		Cl = rotateLeft(Cl + H(Dl, El, Al) + x[8] + 0x6ed9eba1, 13) + Bl;
		El = rotateLeft(El, 10);
		Bl = rotateLeft(Bl + H(Cl, Dl, El) + x[1] + 0x6ed9eba1, 15) + Al;
		Dl = rotateLeft(Dl, 10);
		Al = rotateLeft(Al + H(Bl, Cl, Dl) + x[2] + 0x6ed9eba1, 14) + El;
		Cl = rotateLeft(Cl, 10);
		El = rotateLeft(El + H(Al, Bl, Cl) + x[7] + 0x6ed9eba1, 8) + Dl;
		Bl = rotateLeft(Bl, 10);
		Dl = rotateLeft(Dl + H(El, Al, Bl) + x[0] + 0x6ed9eba1, 13) + Cl;
		Al = rotateLeft(Al, 10);
		Cl = rotateLeft(Cl + H(Dl, El, Al) + x[6] + 0x6ed9eba1, 6) + Bl;
		El = rotateLeft(El, 10);
		Bl = rotateLeft(Bl + H(Cl, Dl, El) + x[13] + 0x6ed9eba1, 5) + Al;
		Dl = rotateLeft(Dl, 10);
		Al = rotateLeft(Al + H(Bl, Cl, Dl) + x[11] + 0x6ed9eba1, 12) + El;
		Cl = rotateLeft(Cl, 10);
		El = rotateLeft(El + H(Al, Bl, Cl) + x[5] + 0x6ed9eba1, 7) + Dl;
		Bl = rotateLeft(Bl, 10);
		Dl = rotateLeft(Dl + H(El, Al, Bl) + x[12] + 0x6ed9eba1, 5) + Cl;
		Al = rotateLeft(Al, 10);

		// rounds 32-47 (right)
		Dr = rotateLeft(Dr + H(Er, Ar, Br) + x[15] + 0x6d703ef3, 9) + Cr;
		Ar = rotateLeft(Ar, 10);
		Cr = rotateLeft(Cr + H(Dr, Er, Ar) + x[5] + 0x6d703ef3, 7) + Br;
		Er = rotateLeft(Er, 10);
		Br = rotateLeft(Br + H(Cr, Dr, Er) + x[1] + 0x6d703ef3, 15) + Ar;
		Dr = rotateLeft(Dr, 10);
		Ar = rotateLeft(Ar + H(Br, Cr, Dr) + x[3] + 0x6d703ef3, 11) + Er;
		Cr = rotateLeft(Cr, 10);
		Er = rotateLeft(Er + H(Ar, Br, Cr) + x[7] + 0x6d703ef3, 8) + Dr;
		Br = rotateLeft(Br, 10);
		Dr = rotateLeft(Dr + H(Er, Ar, Br) + x[14] + 0x6d703ef3, 6) + Cr;
		Ar = rotateLeft(Ar, 10);
		Cr = rotateLeft(Cr + H(Dr, Er, Ar) + x[6] + 0x6d703ef3, 6) + Br;
		Er = rotateLeft(Er, 10);
		Br = rotateLeft(Br + H(Cr, Dr, Er) + x[9] + 0x6d703ef3, 14) + Ar;
		Dr = rotateLeft(Dr, 10);
		Ar = rotateLeft(Ar + H(Br, Cr, Dr) + x[11] + 0x6d703ef3, 12) + Er;
		Cr = rotateLeft(Cr, 10);
		Er = rotateLeft(Er + H(Ar, Br, Cr) + x[8] + 0x6d703ef3, 13) + Dr;
		Br = rotateLeft(Br, 10);
		Dr = rotateLeft(Dr + H(Er, Ar, Br) + x[12] + 0x6d703ef3, 5) + Cr;
		Ar = rotateLeft(Ar, 10);
		Cr = rotateLeft(Cr + H(Dr, Er, Ar) + x[2] + 0x6d703ef3, 14) + Br;
		Er = rotateLeft(Er, 10);
		Br = rotateLeft(Br + H(Cr, Dr, Er) + x[10] + 0x6d703ef3, 13) + Ar;
		Dr = rotateLeft(Dr, 10);
		Ar = rotateLeft(Ar + H(Br, Cr, Dr) + x[0] + 0x6d703ef3, 13) + Er;
		Cr = rotateLeft(Cr, 10);
		Er = rotateLeft(Er + H(Ar, Br, Cr) + x[4] + 0x6d703ef3, 7) + Dr;
		Br = rotateLeft(Br, 10);
		Dr = rotateLeft(Dr + H(Er, Ar, Br) + x[13] + 0x6d703ef3, 5) + Cr;
		Ar = rotateLeft(Ar, 10);

		// rounds 48-63 (left)
		Cl = rotateLeft(Cl + K(Dl, El, Al) + x[1] + 0x8f1bbcdc, 11) + Bl;
		El = rotateLeft(El, 10);
		Bl = rotateLeft(Bl + K(Cl, Dl, El) + x[9] + 0x8f1bbcdc, 12) + Al;
		Dl = rotateLeft(Dl, 10);
		Al = rotateLeft(Al + K(Bl, Cl, Dl) + x[11] + 0x8f1bbcdc, 14) + El;
		Cl = rotateLeft(Cl, 10);
		El = rotateLeft(El + K(Al, Bl, Cl) + x[10] + 0x8f1bbcdc, 15) + Dl;
		Bl = rotateLeft(Bl, 10);
		Dl = rotateLeft(Dl + K(El, Al, Bl) + x[0] + 0x8f1bbcdc, 14) + Cl;
		Al = rotateLeft(Al, 10);
		Cl = rotateLeft(Cl + K(Dl, El, Al) + x[8] + 0x8f1bbcdc, 15) + Bl;
		El = rotateLeft(El, 10);
		Bl = rotateLeft(Bl + K(Cl, Dl, El) + x[12] + 0x8f1bbcdc, 9) + Al;
		Dl = rotateLeft(Dl, 10);
		Al = rotateLeft(Al + K(Bl, Cl, Dl) + x[4] + 0x8f1bbcdc, 8) + El;
		Cl = rotateLeft(Cl, 10);
		El = rotateLeft(El + K(Al, Bl, Cl) + x[13] + 0x8f1bbcdc, 9) + Dl;
		Bl = rotateLeft(Bl, 10);
		Dl = rotateLeft(Dl + K(El, Al, Bl) + x[3] + 0x8f1bbcdc, 14) + Cl;
		Al = rotateLeft(Al, 10);
		Cl = rotateLeft(Cl + K(Dl, El, Al) + x[7] + 0x8f1bbcdc, 5) + Bl;
		El = rotateLeft(El, 10);
		Bl = rotateLeft(Bl + K(Cl, Dl, El) + x[15] + 0x8f1bbcdc, 6) + Al;
		Dl = rotateLeft(Dl, 10);
		Al = rotateLeft(Al + K(Bl, Cl, Dl) + x[14] + 0x8f1bbcdc, 8) + El;
		Cl = rotateLeft(Cl, 10);
		El = rotateLeft(El + K(Al, Bl, Cl) + x[5] + 0x8f1bbcdc, 6) + Dl;
		Bl = rotateLeft(Bl, 10);
		Dl = rotateLeft(Dl + K(El, Al, Bl) + x[6] + 0x8f1bbcdc, 5) + Cl;
		Al = rotateLeft(Al, 10);
		Cl = rotateLeft(Cl + K(Dl, El, Al) + x[2] + 0x8f1bbcdc, 12) + Bl;
		El = rotateLeft(El, 10);

		// rounds 48-63 (right)
		Cr = rotateLeft(Cr + G(Dr, Er, Ar) + x[8] + 0x7a6d76e9, 15) + Br;
		Er = rotateLeft(Er, 10);
		Br = rotateLeft(Br + G(Cr, Dr, Er) + x[6] + 0x7a6d76e9, 5) + Ar;
		Dr = rotateLeft(Dr, 10);
		Ar = rotateLeft(Ar + G(Br, Cr, Dr) + x[4] + 0x7a6d76e9, 8) + Er;
		Cr = rotateLeft(Cr, 10);
		Er = rotateLeft(Er + G(Ar, Br, Cr) + x[1] + 0x7a6d76e9, 11) + Dr;
		Br = rotateLeft(Br, 10);
		Dr = rotateLeft(Dr + G(Er, Ar, Br) + x[3] + 0x7a6d76e9, 14) + Cr;
		Ar = rotateLeft(Ar, 10);
		Cr = rotateLeft(Cr + G(Dr, Er, Ar) + x[11] + 0x7a6d76e9, 14) + Br;
		Er = rotateLeft(Er, 10);
		Br = rotateLeft(Br + G(Cr, Dr, Er) + x[15] + 0x7a6d76e9, 6) + Ar;
		Dr = rotateLeft(Dr, 10);
		Ar = rotateLeft(Ar + G(Br, Cr, Dr) + x[0] + 0x7a6d76e9, 14) + Er;
		Cr = rotateLeft(Cr, 10);
		Er = rotateLeft(Er + G(Ar, Br, Cr) + x[5] + 0x7a6d76e9, 6) + Dr;
		Br = rotateLeft(Br, 10);
		Dr = rotateLeft(Dr + G(Er, Ar, Br) + x[12] + 0x7a6d76e9, 9) + Cr;
		Ar = rotateLeft(Ar, 10);
		Cr = rotateLeft(Cr + G(Dr, Er, Ar) + x[2] + 0x7a6d76e9, 12) + Br;
		Er = rotateLeft(Er, 10);
		Br = rotateLeft(Br + G(Cr, Dr, Er) + x[13] + 0x7a6d76e9, 9) + Ar;
		Dr = rotateLeft(Dr, 10);
		Ar = rotateLeft(Ar + G(Br, Cr, Dr) + x[9] + 0x7a6d76e9, 12) + Er;
		Cr = rotateLeft(Cr, 10);
		Er = rotateLeft(Er + G(Ar, Br, Cr) + x[7] + 0x7a6d76e9, 5) + Dr;
		Br = rotateLeft(Br, 10);
		Dr = rotateLeft(Dr + G(Er, Ar, Br) + x[10] + 0x7a6d76e9, 15) + Cr;
		Ar = rotateLeft(Ar, 10);
		Cr = rotateLeft(Cr + G(Dr, Er, Ar) + x[14] + 0x7a6d76e9, 8) + Br;
		Er = rotateLeft(Er, 10);

		// rounds 64-79 (left)
		Bl = rotateLeft(Bl + L(Cl, Dl, El) + x[4] + 0xa953fd4e, 9) + Al;
		Dl = rotateLeft(Dl, 10);
		Al = rotateLeft(Al + L(Bl, Cl, Dl) + x[0] + 0xa953fd4e, 15) + El;
		Cl = rotateLeft(Cl, 10);
		El = rotateLeft(El + L(Al, Bl, Cl) + x[5] + 0xa953fd4e, 5) + Dl;
		Bl = rotateLeft(Bl, 10);
		Dl = rotateLeft(Dl + L(El, Al, Bl) + x[9] + 0xa953fd4e, 11) + Cl;
		Al = rotateLeft(Al, 10);
		Cl = rotateLeft(Cl + L(Dl, El, Al) + x[7] + 0xa953fd4e, 6) + Bl;
		El = rotateLeft(El, 10);
		Bl = rotateLeft(Bl + L(Cl, Dl, El) + x[12] + 0xa953fd4e, 8) + Al;
		Dl = rotateLeft(Dl, 10);
		Al = rotateLeft(Al + L(Bl, Cl, Dl) + x[2] + 0xa953fd4e, 13) + El;
		Cl = rotateLeft(Cl, 10);
		El = rotateLeft(El + L(Al, Bl, Cl) + x[10] + 0xa953fd4e, 12) + Dl;
		Bl = rotateLeft(Bl, 10);
		Dl = rotateLeft(Dl + L(El, Al, Bl) + x[14] + 0xa953fd4e, 5) + Cl;
		Al = rotateLeft(Al, 10);
		Cl = rotateLeft(Cl + L(Dl, El, Al) + x[1] + 0xa953fd4e, 12) + Bl;
		El = rotateLeft(El, 10);
		Bl = rotateLeft(Bl + L(Cl, Dl, El) + x[3] + 0xa953fd4e, 13) + Al;
		Dl = rotateLeft(Dl, 10);
		Al = rotateLeft(Al + L(Bl, Cl, Dl) + x[8] + 0xa953fd4e, 14) + El;
		Cl = rotateLeft(Cl, 10);
		El = rotateLeft(El + L(Al, Bl, Cl) + x[11] + 0xa953fd4e, 11) + Dl;
		Bl = rotateLeft(Bl, 10);
		Dl = rotateLeft(Dl + L(El, Al, Bl) + x[6] + 0xa953fd4e, 8) + Cl;
		Al = rotateLeft(Al, 10);
		Cl = rotateLeft(Cl + L(Dl, El, Al) + x[15] + 0xa953fd4e, 5) + Bl;
		El = rotateLeft(El, 10);
		Bl = rotateLeft(Bl + L(Cl, Dl, El) + x[13] + 0xa953fd4e, 6) + Al;
		Dl = rotateLeft(Dl, 10);

		// rounds 64-79 (right)
		Br = rotateLeft(Br + F(Cr, Dr, Er) + x[12], 8) + Ar;
		Dr = rotateLeft(Dr, 10);
		Ar = rotateLeft(Ar + F(Br, Cr, Dr) + x[15], 5) + Er;
		Cr = rotateLeft(Cr, 10);
		Er = rotateLeft(Er + F(Ar, Br, Cr) + x[10], 12) + Dr;
		Br = rotateLeft(Br, 10);
		Dr = rotateLeft(Dr + F(Er, Ar, Br) + x[4], 9) + Cr;
		Ar = rotateLeft(Ar, 10);
		Cr = rotateLeft(Cr + F(Dr, Er, Ar) + x[1], 12) + Br;
		Er = rotateLeft(Er, 10);
		Br = rotateLeft(Br + F(Cr, Dr, Er) + x[5], 5) + Ar;
		Dr = rotateLeft(Dr, 10);
		Ar = rotateLeft(Ar + F(Br, Cr, Dr) + x[8], 14) + Er;
		Cr = rotateLeft(Cr, 10);
		Er = rotateLeft(Er + F(Ar, Br, Cr) + x[7], 6) + Dr;
		Br = rotateLeft(Br, 10);
		Dr = rotateLeft(Dr + F(Er, Ar, Br) + x[6], 8) + Cr;
		Ar = rotateLeft(Ar, 10);
		Cr = rotateLeft(Cr + F(Dr, Er, Ar) + x[2], 13) + Br;
		Er = rotateLeft(Er, 10);
		Br = rotateLeft(Br + F(Cr, Dr, Er) + x[13], 6) + Ar;
		Dr = rotateLeft(Dr, 10);
		Ar = rotateLeft(Ar + F(Br, Cr, Dr) + x[14], 5) + Er;
		Cr = rotateLeft(Cr, 10);
		Er = rotateLeft(Er + F(Ar, Br, Cr) + x[0], 15) + Dr;
		Br = rotateLeft(Br, 10);
		Dr = rotateLeft(Dr + F(Er, Ar, Br) + x[3], 13) + Cr;
		Ar = rotateLeft(Ar, 10);
		Cr = rotateLeft(Cr + F(Dr, Er, Ar) + x[9], 11) + Br;
		Er = rotateLeft(Er, 10);
		Br = rotateLeft(Br + F(Cr, Dr, Er) + x[11], 11) + Ar;
		Dr = rotateLeft(Dr, 10);

		Bl += state[0] + Cr;
		state[0] = state[1] + Cl + Dr;
		state[1] = state[2] + Dl + Er;
		state[2] = state[3] + El + Ar;
		state[3] = state[4] + Al + Br;
		state[4] = Bl;
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

	private static int L(int u, int v, int w) {
		return u ^ (v | ~w);
	}

}
