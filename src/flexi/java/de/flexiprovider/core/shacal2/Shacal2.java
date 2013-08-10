/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */
package de.flexiprovider.core.shacal2;

import de.flexiprovider.api.BlockCipher;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.keys.Key;
import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.api.keys.SecretKeySpec;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.util.BigEndianConversions;

/**
 * SHACAL-2 is 256-bit symmetric block cipher with a SHA-2 structure, jointly
 * developed by Helena Handschuh and David Naccache. It supports keys of various
 * lengths (between 128 and 512 bits). Encrypting and decryption of a block of
 * data is achieved in 64 rounds.
 * <p>
 * For more information, <a
 * href="https://www.cosic.esat.kuleuven.be/nessie/Bookv015.pdf">see here</a>.
 * 
 * @author Paul Nguentcheu
 */
public class Shacal2 extends BlockCipher {

	/**
	 * The algorithm name.
	 */
	public static final String ALG_NAME = "Shacal2";

	/**
	 * Constant words K<sub>0...63</sub>
	 * 
	 * These are the first thirty-two bits of the fractional parts of the cube
	 * roots of the first sixty-four primes.
	 */
	int[] K = { 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
			0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
			0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
			0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
			0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
			0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
			0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
			0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
			0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
			0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
			0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
			0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
			0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

	// 32 bytes = 256 bits
	private static final int BLOCK_SIZE = 32;

	private int[] W = new int[64];

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
	 * or in decryption mode. The blocksize in Shacal2 is always 32 bytes.
	 * 
	 * @return the used blocksize
	 */
	protected int getCipherBlockSize() {
		return BLOCK_SIZE; // The blocksize is always 32 bytes
	}

	/**
	 * Returns the key size of the given key object. Checks whether the key
	 * object is an instance of <code>Shacal2Key</code> or
	 * <code>SecretKeySpec</code>.
	 * 
	 * @param key
	 *            the key object
	 * @return the key size of the given key object.
	 * @throws InvalidKeyException
	 *             if the key is invalid.
	 */
	public int getKeySize(Key key) throws InvalidKeyException {
		if (!((key instanceof Shacal2Key) || (key instanceof SecretKeySpec))) {
			throw new InvalidKeyException("not a Shacal2 Key");
		}

		int keyLen = key.getEncoded().length;

		if (keyLen != 16 && keyLen != 24 && keyLen != 32 && keyLen != 40
				&& keyLen != 48 && keyLen != 64) {
			throw new InvalidKeyException("invalid key size");
		}
		return keyLen << 3;
	}

	/**
	 * This method implements the Shacal2 Key schedule.
	 * 
	 * @param key
	 *            the byte array containing the data for the key.
	 */
	public void keySchedule(byte[] key) {
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

		W[0] = ((buffer[0] & 0xff) << 24) | (buffer[1] & 0xff) << 16
				| (buffer[2] & 0xff) << 8 | (buffer[3] & 0xff);
		W[1] = ((buffer[4] & 0xff) << 24) | (buffer[5] & 0xff) << 16
				| (buffer[6] & 0xff) << 8 | (buffer[7] & 0xff);
		W[2] = ((buffer[8] & 0xff) << 24) | (buffer[9] & 0xff) << 16
				| (buffer[10] & 0xff) << 8 | (buffer[11] & 0xff);
		W[3] = ((buffer[12] & 0xff) << 24) | (buffer[13] & 0xff) << 16
				| (buffer[14] & 0xff) << 8 | (buffer[15] & 0xff);
		W[4] = ((buffer[16] & 0xff) << 24) | (buffer[17] & 0xff) << 16
				| (buffer[18] & 0xff) << 8 | (buffer[19] & 0xff);
		W[5] = ((buffer[20] & 0xff) << 24) | (buffer[21] & 0xff) << 16
				| (buffer[22] & 0xff) << 8 | (buffer[23] & 0xff);
		W[6] = ((buffer[24] & 0xff) << 24) | (buffer[25] & 0xff) << 16
				| (buffer[26] & 0xff) << 8 | (buffer[27] & 0xff);
		W[7] = ((buffer[28] & 0xff) << 24) | (buffer[29] & 0xff) << 16
				| (buffer[30] & 0xff) << 8 | (buffer[31] & 0xff);
		W[8] = ((buffer[32] & 0xff) << 24) | (buffer[33] & 0xff) << 16
				| (buffer[34] & 0xff) << 8 | (buffer[35] & 0xff);
		W[9] = ((buffer[36] & 0xff) << 24) | (buffer[37] & 0xff) << 16
				| (buffer[38] & 0xff) << 8 | (buffer[39] & 0xff);
		W[10] = ((buffer[40] & 0xff) << 24) | (buffer[41] & 0xff) << 16
				| (buffer[42] & 0xff) << 8 | (buffer[43] & 0xff);
		W[11] = ((buffer[44] & 0xff) << 24) | (buffer[45] & 0xff) << 16
				| (buffer[46] & 0xff) << 8 | (buffer[47] & 0xff);
		W[12] = ((buffer[48] & 0xff) << 24) | (buffer[49] & 0xff) << 16
				| (buffer[50] & 0xff) << 8 | (buffer[51] & 0xff);
		W[13] = ((buffer[52] & 0xff) << 24) | (buffer[53] & 0xff) << 16
				| (buffer[54] & 0xff) << 8 | (buffer[55] & 0xff);
		W[14] = ((buffer[56] & 0xff) << 24) | (buffer[57] & 0xff) << 16
				| (buffer[58] & 0xff) << 8 | (buffer[59] & 0xff);
		W[15] = ((buffer[60] & 0xff) << 24) | (buffer[61] & 0xff) << 16
				| (buffer[62] & 0xff) << 8 | (buffer[63] & 0xff);

		for (int i = 16; i < 64; i++) {
			W[i] = sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16];
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
	 * @throws InvalidKeyException
	 *             if the given key is inappropriate for initializing this
	 *             cipher.
	 */
	protected void initCipherEncrypt(SecretKey key,
			AlgorithmParameterSpec params) throws InvalidKeyException {
		if (!(key instanceof Shacal2Key)) {
			throw new InvalidKeyException("not a Shacal2 Key");
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
	 *             if the given key is inappropriate for initializing this
	 *             cipher.
	 */
	protected void initCipherDecrypt(SecretKey key,
			AlgorithmParameterSpec params) throws InvalidKeyException {
		initCipherEncrypt(key, params);
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
		int T1, T2, tmp;
		int a, b, c, d, e, f, g, h;

		a = BigEndianConversions.OS2IP(input, 0 + inOff);
		b = BigEndianConversions.OS2IP(input, 4 + inOff);
		c = BigEndianConversions.OS2IP(input, 8 + inOff);
		d = BigEndianConversions.OS2IP(input, 12 + inOff);
		e = BigEndianConversions.OS2IP(input, 16 + inOff);
		f = BigEndianConversions.OS2IP(input, 20 + inOff);
		g = BigEndianConversions.OS2IP(input, 24 + inOff);
		h = BigEndianConversions.OS2IP(input, 28 + inOff);

		for (int i = 63; i >= 0; i--) {
			tmp = a;
			a = b;
			b = c;
			c = d;
			T2 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10))
					+ (a & b ^ a & c ^ b & c);
			T1 = tmp - T2;
			d = e - T1;
			e = f;
			f = g;
			g = h;
			h = T1
					- ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7))
					- (e & f ^ ~e & g) - K[i] - W[i];

		}

		// tmp = a - T2(b, c, d); e = e - tmp; a = tmp - T1(f, g, h, K[63],
		// W[63]);
		// tmp = b - T2(c, d, e); f = f - tmp; b = tmp - T1(g, h, a, K[62],
		// W[62]);
		// tmp = c - T2(d, e, f); g = g - tmp; c = tmp - T1(h, a, b, K[61],
		// W[61]);
		// tmp = d - T2(e, f, g); h = h - tmp; d = tmp - T1(a, b, c, K[60],
		// W[60]);
		// tmp = e - T2(f, g, h); a = a - tmp; e = tmp - T1(b, c, d, K[59],
		// W[59]);
		// tmp = f - T2(g, h, a); b = b - tmp; f = tmp - T1(c, d, e, K[58],
		// W[58]);
		// tmp = g - T2(h, a, b); c = c - tmp; g = tmp - T1(d, e, f, K[57],
		// W[57]);
		// tmp = h - T2(a, b, c); d = d - tmp; h = tmp - T1(e, f, g, K[56],
		// W[56]);
		//    
		//  
		// tmp = a - T2(b, c, d); e = e - tmp; a = tmp - T1(f, g, h, K[55],
		// W[55]);
		// tmp = b - T2(c, d, e); f = f - tmp; b = tmp - T1(g, h, a, K[54],
		// W[54]);
		// tmp = c - T2(d, e, f); g = g - tmp; c = tmp - T1(h, a, b, K[53],
		// W[53]);
		// tmp = d - T2(e, f, g); h = h - tmp; d = tmp - T1(a, b, c, K[52],
		// W[52]);
		// tmp = e - T2(f, g, h); a = a - tmp; e = tmp - T1(b, c, d, K[51],
		// W[51]);
		// tmp = f - T2(g, h, a); b = b - tmp; f = tmp - T1(c, d, e, K[50],
		// W[50]);
		// tmp = g - T2(h, a, b); c = c - tmp; g = tmp - T1(d, e, f, K[49],
		// W[49]);
		// tmp = h - T2(a, b, c); d = d - tmp; h = tmp - T1(e, f, g, K[48],
		// W[48]);
		//    
		// tmp = a - T2(b, c, d); e = e - tmp; a = tmp - T1(f, g, h, K[47],
		// W[47]);
		// tmp = b - T2(c, d, e); f = f - tmp; b = tmp - T1(g, h, a, K[46],
		// W[46]);
		// tmp = c - T2(d, e, f); g = g - tmp; c = tmp - T1(h, a, b, K[45],
		// W[45]);
		// tmp = d - T2(e, f, g); h = h - tmp; d = tmp - T1(a, b, c, K[44],
		// W[44]);
		// tmp = e - T2(f, g, h); a = a - tmp; e = tmp - T1(b, c, d, K[43],
		// W[43]);
		// tmp = f - T2(g, h, a); b = b - tmp; f = tmp - T1(c, d, e, K[42],
		// W[42]);
		// tmp = g - T2(h, a, b); c = c - tmp; g = tmp - T1(d, e, f, K[41],
		// W[41]);
		// tmp = h - T2(a, b, c); d = d - tmp; h = tmp - T1(e, f, g, K[40],
		// W[40]);
		//    
		// tmp = a - T2(b, c, d); e = e - tmp; a = tmp - T1(f, g, h, K[39],
		// W[39]);
		// tmp = b - T2(c, d, e); f = f - tmp; b = tmp - T1(g, h, a, K[38],
		// W[38]);
		// tmp = c - T2(d, e, f); g = g - tmp; c = tmp - T1(h, a, b, K[37],
		// W[37]);
		// tmp = d - T2(e, f, g); h = h - tmp; d = tmp - T1(a, b, c, K[36],
		// W[36]);
		// tmp = e - T2(f, g, h); a = a - tmp; e = tmp - T1(b, c, d, K[35],
		// W[35]);
		// tmp = f - T2(g, h, a); b = b - tmp; f = tmp - T1(c, d, e, K[34],
		// W[34]);
		// tmp = g - T2(h, a, b); c = c - tmp; g = tmp - T1(d, e, f, K[33],
		// W[33]);
		// tmp = h - T2(a, b, c); d = d - tmp; h = tmp - T1(e, f, g, K[32],
		// W[32]);
		//    
		// tmp = a - T2(b, c, d); e = e - tmp; a = tmp - T1(f, g, h, K[31],
		// W[31]);
		// tmp = b - T2(c, d, e); f = f - tmp; b = tmp - T1(g, h, a, K[30],
		// W[30]);
		// tmp = c - T2(d, e, f); g = g - tmp; c = tmp - T1(h, a, b, K[29],
		// W[29]);
		// tmp = d - T2(e, f, g); h = h - tmp; d = tmp - T1(a, b, c, K[28],
		// W[28]);
		// tmp = e - T2(f, g, h); a = a - tmp; e = tmp - T1(b, c, d, K[27],
		// W[27]);
		// tmp = f - T2(g, h, a); b = b - tmp; f = tmp - T1(c, d, e, K[26],
		// W[26]);
		// tmp = g - T2(h, a, b); c = c - tmp; g = tmp - T1(d, e, f, K[25],
		// W[25]);
		// tmp = h - T2(a, b, c); d = d - tmp; h = tmp - T1(e, f, g, K[24],
		// W[24]);
		//    
		// tmp = a - T2(b, c, d); e = e - tmp; a = tmp - T1(f, g, h, K[23],
		// W[23]);
		// tmp = b - T2(c, d, e); f = f - tmp; b = tmp - T1(g, h, a, K[22],
		// W[22]);
		// tmp = c - T2(d, e, f); g = g - tmp; c = tmp - T1(h, a, b, K[21],
		// W[21]);
		// tmp = d - T2(e, f, g); h = h - tmp; d = tmp - T1(a, b, c, K[20],
		// W[20]);
		// tmp = e - T2(f, g, h); a = a - tmp; e = tmp - T1(b, c, d, K[19],
		// W[19]);
		// tmp = f - T2(g, h, a); b = b - tmp; f = tmp - T1(c, d, e, K[18],
		// W[18]);
		// tmp = g - T2(h, a, b); c = c - tmp; g = tmp - T1(d, e, f, K[17],
		// W[17]);
		// tmp = h - T2(a, b, c); d = d - tmp; h = tmp - T1(e, f, g, K[16],
		// W[16]);
		//    
		// tmp = a - T2(b, c, d); e = e - tmp; a = tmp - T1(f, g, h, K[15],
		// W[15]);
		// tmp = b - T2(c, d, e); f = f - tmp; b = tmp - T1(g, h, a, K[14],
		// W[14]);
		// tmp = c - T2(d, e, f); g = g - tmp; c = tmp - T1(h, a, b, K[13],
		// W[13]);
		// tmp = d - T2(e, f, g); h = h - tmp; d = tmp - T1(a, b, c, K[12],
		// W[12]);
		// tmp = e - T2(f, g, h); a = a - tmp; e = tmp - T1(b, c, d, K[11],
		// W[11]);
		// tmp = f - T2(g, h, a); b = b - tmp; f = tmp - T1(c, d, e, K[10],
		// W[10]);
		// tmp = g - T2(h, a, b); c = c - tmp; g = tmp - T1(d, e, f, K[ 9], W[
		// 9]);
		// tmp = h - T2(a, b, c); d = d - tmp; h = tmp - T1(e, f, g, K[ 8], W[
		// 8]);
		//    
		// tmp = a - T2(b, c, d); e = e - tmp; a = tmp - T1(f, g, h, K[ 7], W[
		// 7]);
		// tmp = b - T2(c, d, e); f = f - tmp; b = tmp - T1(g, h, a, K[ 6], W[
		// 6]);
		// tmp = c - T2(d, e, f); g = g - tmp; c = tmp - T1(h, a, b, K[ 5], W[
		// 5]);
		// tmp = d - T2(e, f, g); h = h - tmp; d = tmp - T1(a, b, c, K[ 4], W[
		// 4]);
		// tmp = e - T2(f, g, h); a = a - tmp; e = tmp - T1(b, c, d, K[ 3], W[
		// 3]);
		// tmp = f - T2(g, h, a); b = b - tmp; f = tmp - T1(c, d, e, K[ 2], W[
		// 2]);
		// tmp = g - T2(h, a, b); c = c - tmp; g = tmp - T1(d, e, f, K[ 1], W[
		// 1]);
		// tmp = h - T2(a, b, c); d = d - tmp; h = tmp - T1(e, f, g, K[ 0], W[
		// 0]);

		BigEndianConversions.I2OSP(a, output, 0 + outOff);
		BigEndianConversions.I2OSP(b, output, 4 + outOff);
		BigEndianConversions.I2OSP(c, output, 8 + outOff);
		BigEndianConversions.I2OSP(d, output, 12 + outOff);
		BigEndianConversions.I2OSP(e, output, 16 + outOff);
		BigEndianConversions.I2OSP(f, output, 20 + outOff);
		BigEndianConversions.I2OSP(g, output, 24 + outOff);
		BigEndianConversions.I2OSP(h, output, 28 + outOff);
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
		int a, b, c, d, e, f, g, h;
		int T1, T2;

		/* steb a */

		a = BigEndianConversions.OS2IP(input, 0 + inOff);
		b = BigEndianConversions.OS2IP(input, 4 + inOff);
		c = BigEndianConversions.OS2IP(input, 8 + inOff);
		d = BigEndianConversions.OS2IP(input, 12 + inOff);
		e = BigEndianConversions.OS2IP(input, 16 + inOff);
		f = BigEndianConversions.OS2IP(input, 20 + inOff);
		g = BigEndianConversions.OS2IP(input, 24 + inOff);
		h = BigEndianConversions.OS2IP(input, 28 + inOff);

		/* step b */
		for (int i = 0; i < 64; i++) {
			T1 = ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7))
					+ (e & f ^ ~e & g) + h + K[i] + W[i];
			T2 = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10))
					+ (a & b ^ a & c ^ b & c);
			// T1 = Sigma1(e) + Ch(e, f, g) + h + K[i]+ W[i];
			// T2 = Sigma0(a) + Maj(a, b, c);
			h = g;
			g = f;
			f = e;
			e = d + T1;
			d = c;
			c = b;
			b = a;
			a = T1 + T2;
		}

		/* step c */

		BigEndianConversions.I2OSP(a, output, 0 + outOff);
		BigEndianConversions.I2OSP(b, output, 4 + outOff);
		BigEndianConversions.I2OSP(c, output, 8 + outOff);
		BigEndianConversions.I2OSP(d, output, 12 + outOff);
		BigEndianConversions.I2OSP(e, output, 16 + outOff);
		BigEndianConversions.I2OSP(f, output, 20 + outOff);
		BigEndianConversions.I2OSP(g, output, 24 + outOff);
		BigEndianConversions.I2OSP(h, output, 28 + outOff);
	}

	private int sigma0(int x) {
		return ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
	}

	private int sigma1(int x) {
		return ((x >>> 17) | (x << 15)) ^ ((x >>> 19) | (x << 13)) ^ (x >>> 10);
	}

}
