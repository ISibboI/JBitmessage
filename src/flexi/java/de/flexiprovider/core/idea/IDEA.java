/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */
package de.flexiprovider.core.idea;

import de.flexiprovider.api.BlockCipher;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.exceptions.NoSuchModeException;
import de.flexiprovider.api.keys.Key;
import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.api.keys.SecretKeySpec;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;

/**
 * BlockCipherIDEA implements the IDEA Cipher. It uses a block size of 64 (8
 * Bytes), a 128 bit key and uses 8 rounds for encryption/decryption.
 * 
 * @author Ralph Kuhnert
 * @author Anders Adamson
 * @author Oliver Seiler
 */
public class IDEA extends BlockCipher {

	/**
	 * The algorithm name.
	 */
	public static final String ALG_NAME = "IDEA";

	/**
	 * The OID of IDEA.
	 */
	public static final String OID = "1.3.6.1.4.1.188.7.1.1";

	private static final int rounds = 8;

	// 52 bytes = 416 bits
	private static final int keyLength = (rounds * 6) + 4;

	private static final int mulModulus = 0x10001;

	private static final int mulMask = 0xffff;

	// 8 bytes = 64 bits
	private static final int blockSize = 8;

	// 16 bytes = 128 bits
	private static final int keySize = 16;

	// Member Variables

	private int[] encr = null; // internal encryption round key schedule

	private int[] decr = null; // internal decryption round key schedule

	/*
	 * Inner classes providing IDEA with predefined modes
	 */

	/**
	 * IDEA_ECB
	 */
	public static class IDEA_ECB extends IDEA {

		/**
		 * The OID of IDEA_ECB.
		 */
		public static final String OID = IDEA.OID + ".1";

		public IDEA_ECB() {
			super("ECB");
		}
	}

	/**
	 * IDEA_CBC
	 */
	public static class IDEA_CBC extends IDEA {

		/**
		 * The OID of IDEA_CBC.
		 */
		public static final String OID = IDEA.OID + ".2";

		public IDEA_CBC() {
			super("CBC");
		}
	}

	/**
	 * IDEA_CFB
	 */
	public static class IDEA_CFB extends IDEA {

		/**
		 * The OID of IDEA_CFB.
		 */
		public static final String OID = IDEA.OID + ".3";

		public IDEA_CFB() {
			super("CFB");
		}
	}

	/**
	 * IDEA_OFB
	 */
	public static class IDEA_OFB extends IDEA {

		/**
		 * The OID of IDEA_OFB.
		 */
		public static final String OID = IDEA.OID + ".4";

		public IDEA_OFB() {
			super("OFB");
		}
	}

	protected IDEA(String modeName) {
		// set the mode
		try {
			setMode(modeName);
		} catch (NoSuchModeException e) {
			throw new RuntimeException("Internal error: could not find mode '"
					+ modeName + "'.");
		}
	}

	/**
	 * Constructor.
	 */
	public IDEA() {
		// empty
	}

	/**
	 * @return the name of this cipher
	 */
	public String getName() {
		return ALG_NAME;
	}

	/**
	 * Return the key size in bits of the given key object. Checks whether the
	 * key object is an instance of <tt>IDEAKey</tt> or <tt>SecretKeySpec</tt>.
	 * The key size for IDEA is always fixed to 128 bits as per the
	 * specification.
	 * 
	 * @param key
	 *            the key object
	 * @return the key size in bits of the given key object
	 * @throws InvalidKeyException
	 *             if key is invalid.
	 */
	public int getKeySize(Key key) throws InvalidKeyException {
		if (!((key instanceof IDEAKey) || (key instanceof SecretKeySpec))) {
			throw new InvalidKeyException("not a IDEA Key");
		}

		return 128;
	}

	/**
	 * @return the block size in bytes of the cipher
	 */
	protected int getCipherBlockSize() {
		return blockSize;
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
		// type checking
		if ((key == null) || !(key instanceof IDEAKey)) {
			throw new InvalidKeyException("unsupported type");
		}

		// compute the encryption key schedule
		encKeySchedule(key.getEncoded());
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
		// initEncrypt() always has to be done, because the decryption key
		// schedule is based on the encryption key schedule. Type checking of
		// the key is performed there.
		initCipherEncrypt(key, null);

		// compute the decryption key schedule
		decKeySchedule();
	}

	/**
	 * This method encrypts a single block of data, and may only be called, if
	 * the block cipher is in encrytion mode. It has to be asured that the array
	 * <TT>in</TT> contains a whole block starting at <TT>inOffset</TT> and that
	 * <TT>out</TT> is large enough to hold an encrypted block starting at
	 * <TT>outOffset</TT>
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
		encryptDecrypt(encr, input, inOff, output, outOff);
	}

	/**
	 * This method decrypts a single block of data, and may only be called, if
	 * the block cipher is in decrytion mode. It has to be asured that the array
	 * <TT>in</TT> contains a whole block starting at <TT>inOffset</TT> and that
	 * <TT>out</TT> is large enough to hold an decrypted block starting at
	 * <TT>outOffset</TT>
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
		encryptDecrypt(decr, input, inOff, output, outOff);
	}

	private void encKeySchedule(byte[] keyBytes) {
		encr = new int[keyLength];

		int i = 0;
		for (; i < keySize >> 1; i++) {
			encr[i] = ((keyBytes[i << 1] & 0xff) << 8)
					| (keyBytes[(i << 1) + 1] & 0xff);
		}

		int j = 0;
		int koff = 0;
		for (; i < keyLength; i++) {
			j++;
			encr[koff + j + 7] = ((encr[koff + (j & 7)] << 9) | (encr[koff
					+ ((j + 1) & 7)] >>> 7)) & 0xffff;
			koff += j & 8;
			j &= 7;
		}
	}

	private void decKeySchedule() {
		decr = new int[keyLength];
		int j = 0;

		decr[6 * rounds + 0] = mulInv(encr[j++]);
		decr[6 * rounds + 1] = -encr[j++];
		decr[6 * rounds + 2] = -encr[j++];
		decr[6 * rounds + 3] = mulInv(encr[j++]);

		for (int i = 6 * (rounds - 1); i >= 0; i -= 6) {
			decr[i + 4] = encr[j++];
			decr[i + 5] = encr[j++];
			decr[i + 0] = mulInv(encr[j++]);
			if (i > 0) {
				decr[i + 2] = -encr[j++];
				decr[i + 1] = -encr[j++];
			} else {
				decr[i + 1] = -encr[j++];
				decr[i + 2] = -encr[j++];
			}
			decr[i + 3] = mulInv(encr[j++]);
		}
	}

	/**
	 * Encryption and decryption
	 */
	private void encryptDecrypt(int[] key, byte[] in, int in_offset,
			byte[] out, int out_offset) {
		int k = 0;
		int t0, t1;

		// Two bytes are merged and put into an integer.
		// Integer is used because java does not support unsigned words.
		// The most significant bytes are unused.

		int x0 = in[in_offset++] << 8;
		x0 |= in[in_offset++] & 0xff;
		int x1 = in[in_offset++] << 8;
		x1 |= in[in_offset++] & 0xff;
		int x2 = in[in_offset++] << 8;
		x2 |= in[in_offset++] & 0xff;
		int x3 = in[in_offset++] << 8;
		x3 |= in[in_offset] & 0xff;

		// Compute the Blocks

		for (int i = 0; i < rounds; ++i) {
			x0 = mulMod16(x0, key[k++]);
			x1 += key[k++];
			x2 += key[k++];
			x3 = mulMod16(x3, key[k++]);

			t0 = x2;
			x2 = mulMod16(x0 ^ x2, key[k++]);
			t1 = x1;
			x1 = mulMod16((x1 ^ x3) + x2, key[k++]);
			x2 += x1;

			x0 ^= x1;
			x3 ^= x2;
			x1 ^= t0;
			x2 ^= t1;
		}

		x0 = mulMod16(x0, key[k++]);
		t0 = x1;
		x1 = x2 + key[k++];
		x2 = t0 + key[k++];
		x3 = mulMod16(x3, key[k]);

		// Reconvertion into bytes

		out[out_offset++] = (byte) (x0 >>> 8);
		out[out_offset++] = (byte) x0;
		out[out_offset++] = (byte) (x1 >>> 8);
		out[out_offset++] = (byte) x1;
		out[out_offset++] = (byte) (x2 >>> 8);
		out[out_offset++] = (byte) x2;
		out[out_offset++] = (byte) (x3 >>> 8);
		out[out_offset] = (byte) x3;
	}

	private int mulInv(int x) {
		int t0, t1, q, y;

		// Cutting of the more significant bits.

		x &= mulMask;

		if (x <= 1) {
			return x;
		}

		t1 = (int) (0x10001L / x); // Since x >= 2, the result is 16 bit
		y = (int) (0x10001L % x);

		if (y == 1) {
			return (1 - t1) & mulMask;
		}

		t0 = 1;
		do {
			q = x / y;
			x %= y;
			t0 = (t0 + (q * t1)) & mulMask;
			if (x == 1) {
				return t0;
			}
			q = y / x;
			y = y % x;
			t1 = (t1 + (q * t0)) & mulMask;
		} while (y != 1);

		return (1 - t1) & mulMask;
	}

	private int mulMod16(int a, int b) {
		int p;

		// Cutting of the more significant bits.

		a &= mulMask;
		b &= mulMask;

		if (a == 0) {
			a = mulModulus - b;
		} else if (b == 0) {
			a = mulModulus - a;
		} else {
			// a *= b;
			// b = a >>> 16;
			// if ((a & MulMask) >= b)
			// a -= b;
			// else
			// a += MulModulus - b;

			p = a * b;
			b = p & mulMask;
			a = p >>> 16;
			a = b - a + (b < a ? 1 : 0);
		}

		return a & mulMask;
	}

}
