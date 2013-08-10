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
 * This class implements the MD5 message digest algorithm according to the
 * Handbook of Applied Cryptography, Menezes, van Oorschot, Vanstone, CRC Press,
 * 1997, algorithm 9.51
 * 
 * <p>
 * The algorithm has been invented by Rivest and further information concerning
 * the MD5 message digest family can be found at <a
 * href="http://www.rsa.com">www.rsa.com</a> and in RFC 1321.
 * 
 * <p>
 * The efficiency of this implementation has been tested on a AMD K6-III, 450
 * MHz, running Windows 98 SE, using jdk 1.2.2. The hashing rate is about 125
 * MBits / second.
 * 
 * @author Oliver Seiler
 */
public final class MD5 extends MDFamilyDigest {

	/**
	 * The algorithm name.
	 */
	public static final String ALG_NAME = "MD5";

	/**
	 * The OID of MD5 (defined by PKCS #2).
	 */
	public static final String OID = "1.2.840.113549.2.5";

	// magic constants for initialization
	private static final int[] initState = { 0x67452301, 0xefcdab89,
			0x98badcfe, 0x10325476 };

	// length of the resulting message digest in bytes
	private static final int MD5_DIGEST_LENGTH = 16;

	// number of bitshifts
	private static final int S11 = 7;

	private static final int S12 = 12;

	private static final int S13 = 17;

	private static final int S14 = 22;

	private static final int S21 = 5;

	private static final int S22 = 9;

	private static final int S23 = 14;

	private static final int S24 = 20;

	private static final int S31 = 4;

	private static final int S32 = 11;

	private static final int S33 = 16;

	private static final int S34 = 23;

	private static final int S41 = 6;

	private static final int S42 = 10;

	private static final int S43 = 15;

	private static final int S44 = 21;

	/**
	 * Constructor.
	 */
	public MD5() {
		super(MD5_DIGEST_LENGTH);
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
		byte[] digest = new byte[MD5_DIGEST_LENGTH];

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
		a = FF(a, b, c, d, x[0], S11, 0xd76aa478); // 1
		d = FF(d, a, b, c, x[1], S12, 0xe8c7b756); // 2
		c = FF(c, d, a, b, x[2], S13, 0x242070db); // 3
		b = FF(b, c, d, a, x[3], S14, 0xc1bdceee); // 4
		a = FF(a, b, c, d, x[4], S11, 0xf57c0faf); // 5
		d = FF(d, a, b, c, x[5], S12, 0x4787c62a); // 6
		c = FF(c, d, a, b, x[6], S13, 0xa8304613); // 7
		b = FF(b, c, d, a, x[7], S14, 0xfd469501); // 8
		a = FF(a, b, c, d, x[8], S11, 0x698098d8); // 9
		d = FF(d, a, b, c, x[9], S12, 0x8b44f7af); // 10
		c = FF(c, d, a, b, x[10], S13, 0xffff5bb1); // 11
		b = FF(b, c, d, a, x[11], S14, 0x895cd7be); // 12
		a = FF(a, b, c, d, x[12], S11, 0x6b901122); // 13
		d = FF(d, a, b, c, x[13], S12, 0xfd987193); // 14
		c = FF(c, d, a, b, x[14], S13, 0xa679438e); // 15
		b = FF(b, c, d, a, x[15], S14, 0x49b40821); // 16

		// Round 2
		a = GG(a, b, c, d, x[1], S21, 0xf61e2562); // 17
		d = GG(d, a, b, c, x[6], S22, 0xc040b340); // 18
		c = GG(c, d, a, b, x[11], S23, 0x265e5a51); // 19
		b = GG(b, c, d, a, x[0], S24, 0xe9b6c7aa); // 20
		a = GG(a, b, c, d, x[5], S21, 0xd62f105d); // 21
		d = GG(d, a, b, c, x[10], S22, 0x02441453); // 22
		c = GG(c, d, a, b, x[15], S23, 0xd8a1e681); // 23
		b = GG(b, c, d, a, x[4], S24, 0xe7d3fbc8); // 24
		a = GG(a, b, c, d, x[9], S21, 0x21e1cde6); // 25
		d = GG(d, a, b, c, x[14], S22, 0xc33707d6); // 26
		c = GG(c, d, a, b, x[3], S23, 0xf4d50d87); // 27
		b = GG(b, c, d, a, x[8], S24, 0x455a14ed); // 28
		a = GG(a, b, c, d, x[13], S21, 0xa9e3e905); // 29
		d = GG(d, a, b, c, x[2], S22, 0xfcefa3f8); // 30
		c = GG(c, d, a, b, x[7], S23, 0x676f02d9); // 31
		b = GG(b, c, d, a, x[12], S24, 0x8d2a4c8a); // 32

		// Round 3
		a = HH(a, b, c, d, x[5], S31, 0xfffa3942); // 33
		d = HH(d, a, b, c, x[8], S32, 0x8771f681); // 34
		c = HH(c, d, a, b, x[11], S33, 0x6d9d6122); // 35
		b = HH(b, c, d, a, x[14], S34, 0xfde5380c); // 36
		a = HH(a, b, c, d, x[1], S31, 0xa4beea44); // 37
		d = HH(d, a, b, c, x[4], S32, 0x4bdecfa9); // 38
		c = HH(c, d, a, b, x[7], S33, 0xf6bb4b60); // 39
		b = HH(b, c, d, a, x[10], S34, 0xbebfbc70); // 40
		a = HH(a, b, c, d, x[13], S31, 0x289b7ec6); // 41
		d = HH(d, a, b, c, x[0], S32, 0xeaa127fa); // 42
		c = HH(c, d, a, b, x[3], S33, 0xd4ef3085); // 43
		b = HH(b, c, d, a, x[6], S34, 0x04881d05); // 44
		a = HH(a, b, c, d, x[9], S31, 0xd9d4d039); // 45
		d = HH(d, a, b, c, x[12], S32, 0xe6db99e5); // 46
		c = HH(c, d, a, b, x[15], S33, 0x1fa27cf8); // 47
		b = HH(b, c, d, a, x[2], S34, 0xc4ac5665); // 48

		// Round 4
		a = II(a, b, c, d, x[0], S41, 0xf4292244); // 49
		d = II(d, a, b, c, x[7], S42, 0x432aff97); // 50
		c = II(c, d, a, b, x[14], S43, 0xab9423a7); // 51
		b = II(b, c, d, a, x[5], S44, 0xfc93a039); // 52
		a = II(a, b, c, d, x[12], S41, 0x655b59c3); // 53
		d = II(d, a, b, c, x[3], S42, 0x8f0ccc92); // 54
		c = II(c, d, a, b, x[10], S43, 0xffeff47d); // 55
		b = II(b, c, d, a, x[1], S44, 0x85845dd1); // 56
		a = II(a, b, c, d, x[8], S41, 0x6fa87e4f); // 57
		d = II(d, a, b, c, x[15], S42, 0xfe2ce6e0); // 58
		c = II(c, d, a, b, x[6], S43, 0xa3014314); // 59
		b = II(b, c, d, a, x[13], S44, 0x4e0811a1); // 60
		a = II(a, b, c, d, x[4], S41, 0xf7537e82); // 61
		d = II(d, a, b, c, x[11], S42, 0xbd3af235); // 62
		c = II(c, d, a, b, x[2], S43, 0x2ad7d2bb); // 63
		b = II(b, c, d, a, x[9], S44, 0xeb86d391); // 64

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
		return (x & z) | (y & ~z);
	}

	private static int H(int x, int y, int z) {
		return x ^ y ^ z;
	}

	private static int I(int x, int y, int z) {
		return y ^ (x | ~z);
	}

	private static int FF(int a, int b, int c, int d, int x, int s, int ac) {
		return rotateLeft(a + F(b, c, d) + x + ac, s) + b;
	}

	private static int GG(int a, int b, int c, int d, int x, int s, int ac) {
		return rotateLeft(a + G(b, c, d) + x + ac, s) + b;
	}

	private static int HH(int a, int b, int c, int d, int x, int s, int ac) {
		return rotateLeft(a + H(b, c, d) + x + ac, s) + b;
	}

	private static int II(int a, int b, int c, int d, int x, int s, int ac) {
		return rotateLeft(a + I(b, c, d) + x + ac, s) + b;
	}

}
