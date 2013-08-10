/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.md;

import de.flexiprovider.common.util.LittleEndianConversions;

/**
 * This class implements the MD4 message digest algorithm according to the
 * Handbook of Applied Cryptography, Menezes, van Oorschot, Vanstone, CRC Press,
 * 1997, algorithm 9.49
 * 
 * <p>
 * The algorithm has been invented by Rivest and further information concerning
 * the MD4 message digest family can be found at <a
 * href="http://www.rsa.com">www.rsa.com</a> and in RFC 1320.
 * 
 * <p>
 * The efficiency of this implementation has been tested on a AMD K6-III, 450
 * MHz, running Windows 98 SE, using jdk 1.2.2. The hashing rate is about 138
 * MBits / second.
 * 
 * @author Oliver Seiler
 */
public final class MD4 extends MDFamilyDigest {

	/**
	 * The algorithm name.
	 */
	public static final String ALG_NAME = "MD4";

	/**
	 * The OID of MD4 (defined by PKCS #2).
	 */
	public static final String OID = "1.2.840.113549.2.4";

	// magic constants for initialization
	private static final int[] initState = { 0x67452301, 0xefcdab89,
			0x98badcfe, 0x10325476 };

	// length of the resulting message digest in bytes
	private static final int MD4_DIGEST_LENGTH = 16;

	// number of bitshifts
	private static final int S11 = 3;

	private static final int S12 = 7;

	private static final int S13 = 11;

	private static final int S14 = 19;

	private static final int S21 = 3;

	private static final int S22 = 5;

	private static final int S23 = 9;

	private static final int S24 = 13;

	private static final int S31 = 3;

	private static final int S32 = 9;

	private static final int S33 = 11;

	private static final int S34 = 15;

	/**
	 * Constructor.
	 */
	public MD4() {
		super(MD4_DIGEST_LENGTH);
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
		byte[] digest = new byte[MD4_DIGEST_LENGTH];

		padMessageDigest();

		// convert digest
		LittleEndianConversions.I2OSP(state[0], digest, 0);
		LittleEndianConversions.I2OSP(state[1], digest, 4);
		LittleEndianConversions.I2OSP(state[2], digest, 8);
		LittleEndianConversions.I2OSP(state[3], digest, 12);

		reset();

		return digest;
	}

	/**
	 * process a block of 64 bytes
	 */
	protected synchronized void processBlock() {
		int a = state[0];
		int b = state[1];
		int c = state[2];
		int d = state[3];

		// Round 1
		a = FF(a, b, c, d, x[0], S11); // 1
		d = FF(d, a, b, c, x[1], S12); // 2
		c = FF(c, d, a, b, x[2], S13); // 3
		b = FF(b, c, d, a, x[3], S14); // 4
		a = FF(a, b, c, d, x[4], S11); // 5
		d = FF(d, a, b, c, x[5], S12); // 6
		c = FF(c, d, a, b, x[6], S13); // 7
		b = FF(b, c, d, a, x[7], S14); // 8
		a = FF(a, b, c, d, x[8], S11); // 9
		d = FF(d, a, b, c, x[9], S12); // 10
		c = FF(c, d, a, b, x[10], S13); // 11
		b = FF(b, c, d, a, x[11], S14); // 12
		a = FF(a, b, c, d, x[12], S11); // 13
		d = FF(d, a, b, c, x[13], S12); // 14
		c = FF(c, d, a, b, x[14], S13); // 15
		b = FF(b, c, d, a, x[15], S14); // 16

		// Round 2
		a = GG(a, b, c, d, x[0], S21); // 17
		d = GG(d, a, b, c, x[4], S22); // 18
		c = GG(c, d, a, b, x[8], S23); // 19
		b = GG(b, c, d, a, x[12], S24); // 20
		a = GG(a, b, c, d, x[1], S21); // 21
		d = GG(d, a, b, c, x[5], S22); // 22
		c = GG(c, d, a, b, x[9], S23); // 23
		b = GG(b, c, d, a, x[13], S24); // 24
		a = GG(a, b, c, d, x[2], S21); // 25
		d = GG(d, a, b, c, x[6], S22); // 26
		c = GG(c, d, a, b, x[10], S23); // 27
		b = GG(b, c, d, a, x[14], S24); // 28
		a = GG(a, b, c, d, x[3], S21); // 29
		d = GG(d, a, b, c, x[7], S22); // 30
		c = GG(c, d, a, b, x[11], S23); // 31
		b = GG(b, c, d, a, x[15], S24); // 32

		// Round 3
		a = HH(a, b, c, d, x[0], S31); // 33
		d = HH(d, a, b, c, x[8], S32); // 34
		c = HH(c, d, a, b, x[4], S33); // 35
		b = HH(b, c, d, a, x[12], S34); // 36
		a = HH(a, b, c, d, x[2], S31); // 37
		d = HH(d, a, b, c, x[10], S32); // 38
		c = HH(c, d, a, b, x[6], S33); // 39
		b = HH(b, c, d, a, x[14], S34); // 40
		a = HH(a, b, c, d, x[1], S31); // 41
		d = HH(d, a, b, c, x[9], S32); // 42
		c = HH(c, d, a, b, x[5], S33); // 43
		b = HH(b, c, d, a, x[13], S34); // 44
		a = HH(a, b, c, d, x[3], S31); // 45
		d = HH(d, a, b, c, x[11], S32); // 46
		c = HH(c, d, a, b, x[7], S33); // 47
		b = HH(b, c, d, a, x[15], S34); // 48

		state[0] += a;
		state[1] += b;
		state[2] += c;
		state[3] += d;

	}

	/* basic conversion functions */

	private static int F(int x, int y, int z) {
		return (x & y) | (~x & z);
	}

	private static int G(int x, int y, int z) {
		return (x & y) | (x & z) | (y & z);
	}

	private static int H(int x, int y, int z) {
		return x ^ y ^ z;
	}

	private static int FF(int a, int b, int c, int d, int x, int s) {
		a += F(b, c, d) + x;
		a = rotateLeft(a, s);
		return a;
	}

	private static int GG(int a, int b, int c, int d, int x, int s) {
		a += G(b, c, d) + x + 0x5a827999;
		a = rotateLeft(a, s);
		return a;
	}

	private static int HH(int a, int b, int c, int d, int x, int s) {
		a += H(b, c, d) + x + 0x6ed9eba1;
		a = rotateLeft(a, s);
		return a;
	}

}
