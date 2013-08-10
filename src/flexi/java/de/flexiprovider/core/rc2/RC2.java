/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.rc2;

import de.flexiprovider.api.BlockCipher;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.exceptions.NoSuchModeException;
import de.flexiprovider.api.keys.Key;
import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.api.keys.SecretKeySpec;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;

/**
 * This class implements the RC2 block-cipher algorithm according to RFC 2268.
 * RC2 was invented by Ronald Rivest for RSA Security in 1987. Further
 * information can be found at <a href="www.rsasecurity.com">RSA Security</a>
 * and in RFC 2268.
 * 
 * <p>
 * The efficiency of this implementation has been tested on a AMD K6-III, 450
 * MHz, running Windows 2000 Prof., using jdk 1.2.2. The encryption/decryption
 * rate is about xxx.x MBits.
 * 
 * @author Oliver Seiler
 * 
 */
public class RC2 extends BlockCipher {

	/**
	 * The algorithm name.
	 */
	public static final String ALG_NAME = "RC2";

	/*
	 * Inner classes providing RC2 with predefined mode and padding
	 */

	/**
	 * RC2_CBC
	 */
	public static class RC2_CBC extends RC2 {

		/**
		 * The OID of RC2_CBC.
		 */
		public static final String OID = "1.2.840.113549.3.2";

		public RC2_CBC() {
			// set the mode
			try {
				setMode("CBC");
			} catch (NoSuchModeException e) {
				throw new RuntimeException(
						"Internal error: could not find mode 'CBC'.");
			}
		}
	}

	private int suppliedKeysizeInBytes; // == T

	private int effectiveKeyBits; // == T1

	private byte[] key = new byte[128]; // == L expanded key

	private int j; // global j for mixing and mashing

	private short[] data = new short[4]; // == r data for en-/decryption

	/**
	 * Block size is 8 bytes.
	 */
	private static final int blockSize = 8;

	private static final byte[] piTable = { (byte) 0xd9, (byte) 0x78,
			(byte) 0xf9, (byte) 0xc4, (byte) 0x19, (byte) 0xdd, (byte) 0xb5,
			(byte) 0xed, (byte) 0x28, (byte) 0xe9, (byte) 0xfd, (byte) 0x79,
			(byte) 0x4a, (byte) 0xa0, (byte) 0xd8, (byte) 0x9d, (byte) 0xc6,
			(byte) 0x7e, (byte) 0x37, (byte) 0x83, (byte) 0x2b, (byte) 0x76,
			(byte) 0x53, (byte) 0x8e, (byte) 0x62, (byte) 0x4c, (byte) 0x64,
			(byte) 0x88, (byte) 0x44, (byte) 0x8b, (byte) 0xfb, (byte) 0xa2,
			(byte) 0x17, (byte) 0x9a, (byte) 0x59, (byte) 0xf5, (byte) 0x87,
			(byte) 0xb3, (byte) 0x4f, (byte) 0x13, (byte) 0x61, (byte) 0x45,
			(byte) 0x6d, (byte) 0x8d, (byte) 0x09, (byte) 0x81, (byte) 0x7d,
			(byte) 0x32, (byte) 0xbd, (byte) 0x8f, (byte) 0x40, (byte) 0xeb,
			(byte) 0x86, (byte) 0xb7, (byte) 0x7b, (byte) 0x0b, (byte) 0xf0,
			(byte) 0x95, (byte) 0x21, (byte) 0x22, (byte) 0x5c, (byte) 0x6b,
			(byte) 0x4e, (byte) 0x82, (byte) 0x54, (byte) 0xd6, (byte) 0x65,
			(byte) 0x93, (byte) 0xce, (byte) 0x60, (byte) 0xb2, (byte) 0x1c,
			(byte) 0x73, (byte) 0x56, (byte) 0xc0, (byte) 0x14, (byte) 0xa7,
			(byte) 0x8c, (byte) 0xf1, (byte) 0xdc, (byte) 0x12, (byte) 0x75,
			(byte) 0xca, (byte) 0x1f, (byte) 0x3b, (byte) 0xbe, (byte) 0xe4,
			(byte) 0xd1, (byte) 0x42, (byte) 0x3d, (byte) 0xd4, (byte) 0x30,
			(byte) 0xa3, (byte) 0x3c, (byte) 0xb6, (byte) 0x26, (byte) 0x6f,
			(byte) 0xbf, (byte) 0x0e, (byte) 0xda, (byte) 0x46, (byte) 0x69,
			(byte) 0x07, (byte) 0x57, (byte) 0x27, (byte) 0xf2, (byte) 0x1d,
			(byte) 0x9b, (byte) 0xbc, (byte) 0x94, (byte) 0x43, (byte) 0x03,
			(byte) 0xf8, (byte) 0x11, (byte) 0xc7, (byte) 0xf6, (byte) 0x90,
			(byte) 0xef, (byte) 0x3e, (byte) 0xe7, (byte) 0x06, (byte) 0xc3,
			(byte) 0xd5, (byte) 0x2f, (byte) 0xc8, (byte) 0x66, (byte) 0x1e,
			(byte) 0xd7, (byte) 0x08, (byte) 0xe8, (byte) 0xea, (byte) 0xde,
			(byte) 0x80, (byte) 0x52, (byte) 0xee, (byte) 0xf7, (byte) 0x84,
			(byte) 0xaa, (byte) 0x72, (byte) 0xac, (byte) 0x35, (byte) 0x4d,
			(byte) 0x6a, (byte) 0x2a, (byte) 0x96, (byte) 0x1a, (byte) 0xd2,
			(byte) 0x71, (byte) 0x5a, (byte) 0x15, (byte) 0x49, (byte) 0x74,
			(byte) 0x4b, (byte) 0x9f, (byte) 0xd0, (byte) 0x5e, (byte) 0x04,
			(byte) 0x18, (byte) 0xa4, (byte) 0xec, (byte) 0xc2, (byte) 0xe0,
			(byte) 0x41, (byte) 0x6e, (byte) 0x0f, (byte) 0x51, (byte) 0xcb,
			(byte) 0xcc, (byte) 0x24, (byte) 0x91, (byte) 0xaf, (byte) 0x50,
			(byte) 0xa1, (byte) 0xf4, (byte) 0x70, (byte) 0x39, (byte) 0x99,
			(byte) 0x7c, (byte) 0x3a, (byte) 0x85, (byte) 0x23, (byte) 0xb8,
			(byte) 0xb4, (byte) 0x7a, (byte) 0xfc, (byte) 0x02, (byte) 0x36,
			(byte) 0x5b, (byte) 0x25, (byte) 0x55, (byte) 0x97, (byte) 0x31,
			(byte) 0x2d, (byte) 0x5d, (byte) 0xfa, (byte) 0x98, (byte) 0xe3,
			(byte) 0x8a, (byte) 0x92, (byte) 0xae, (byte) 0x05, (byte) 0xdf,
			(byte) 0x29, (byte) 0x10, (byte) 0x67, (byte) 0x6c, (byte) 0xba,
			(byte) 0xc9, (byte) 0xd3, (byte) 0x00, (byte) 0xe6, (byte) 0xcf,
			(byte) 0xe1, (byte) 0x9e, (byte) 0xa8, (byte) 0x2c, (byte) 0x63,
			(byte) 0x16, (byte) 0x01, (byte) 0x3f, (byte) 0x58, (byte) 0xe2,
			(byte) 0x89, (byte) 0xa9, (byte) 0x0d, (byte) 0x38, (byte) 0x34,
			(byte) 0x1b, (byte) 0xab, (byte) 0x33, (byte) 0xff, (byte) 0xb0,
			(byte) 0xbb, (byte) 0x48, (byte) 0x0c, (byte) 0x5f, (byte) 0xb9,
			(byte) 0xb1, (byte) 0xcd, (byte) 0x2e, (byte) 0xc5, (byte) 0xf3,
			(byte) 0xdb, (byte) 0x47, (byte) 0xe5, (byte) 0xa5, (byte) 0x9c,
			(byte) 0x77, (byte) 0x0a, (byte) 0xa6, (byte) 0x20, (byte) 0x68,
			(byte) 0xfe, (byte) 0x7f, (byte) 0xc1, (byte) 0xad };

	/**
	 * @return the name of this cipher
	 */
	public String getName() {
		return ALG_NAME;
	}

	/**
	 * Returns the key size of the given key object. Checks whether the key
	 * object is an instance of <tt>RC2Key</tt> or <tt>SecretKeySpec</tt>.
	 * 
	 * @param key
	 *            the key object
	 * @return the key size of the given key object.
	 * @throws InvalidKeyException
	 *             if key is invalid.
	 */
	public int getKeySize(Key key) throws InvalidKeyException {
		if ((!(key instanceof RC2Key)) && (!(key instanceof SecretKeySpec))) {
			throw new InvalidKeyException("Not a RC2 Key");
		}

		return key.getEncoded().length << 3;
	}

	/**
	 * This method returns the blocksize the algorithm uses. This method will
	 * normally be called by the padding scheme.
	 * 
	 * @return used blocksize in bytes
	 */
	public int getCipherBlockSize() {
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
		if (!(key instanceof RC2Key)) {
			throw new InvalidKeyException("Not a RC2 Key");
		}

		byte[] encodedKey = key.getEncoded();
		suppliedKeysizeInBytes = encodedKey.length;
		effectiveKeyBits = 8 * suppliedKeysizeInBytes;

		keySchedule(encodedKey);
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
	 * shedule the RC2 key
	 */
	private void keySchedule(byte[] userKey) {
		int keyMask; // == TM
		int keysizeInBytes; // == T8
		int i;

		keysizeInBytes = (effectiveKeyBits + 7) >> 3;
		keyMask = 0xff >>> (8 * keysizeInBytes - effectiveKeyBits);

		for (i = 0; i < suppliedKeysizeInBytes; i++) {
			key[i] = userKey[i];
		}

		for (i = suppliedKeysizeInBytes; i <= 127; i++) {
			key[i] = piTable[(key[i - 1] + key[i - suppliedKeysizeInBytes]) & 0xff];
		}
		key[128 - keysizeInBytes] = piTable[key[128 - keysizeInBytes] & keyMask];
		for (i = 127 - keysizeInBytes; i >= 0; i--) {
			key[i] = piTable[(key[i + 1] ^ key[i + keysizeInBytes]) & 0xff];
		}
	}

	/**
	 * This method encrypts a single block of data, and may only be called, when
	 * the block cipher is in encrytion mode. It has to be asured, too, that the
	 * array <tt>in</tt> contains a whole block starting at <tt>inOffset</tt>
	 * and that <tt>out</tt> is large enogh to hold an encrypted block starting
	 * at <tt>outOffset</tt>
	 * 
	 * @param in
	 *            byte[] containing the plaintext to be encrypted starting at
	 *            inOffset
	 * @param inOffset
	 *            int index in the array in where the plaintext block starts
	 * @param out
	 *            byte[] which will contain the ciphertext startig at outOffset
	 * @param outOffset
	 *            int index in the array out where the ciphertext block will
	 *            start
	 */
	protected void singleBlockEncrypt(byte[] in, int inOffset, byte[] out,
			int outOffset) {
		data[0] = bytesToShort(in, inOffset);
		data[1] = bytesToShort(in, inOffset + 2);
		data[2] = bytesToShort(in, inOffset + 4);
		data[3] = bytesToShort(in, inOffset + 6);
		j = 0;
		mix();
		mix();
		mix();
		mix();
		mix();
		mash();
		mix();
		mix();
		mix();
		mix();
		mix();
		mix();
		mash();
		mix();
		mix();
		mix();
		mix();
		mix();
		shortToBytes(out, outOffset, data[0]);
		shortToBytes(out, outOffset + 2, data[1]);
		shortToBytes(out, outOffset + 4, data[2]);
		shortToBytes(out, outOffset + 6, data[3]);
	}

	/**
	 * This method decrypts a single block of data, and may only be called, when
	 * the block cipher is in decrytion mode. It has to be asured, too, that the
	 * array <tt>in</tt> contains a whole block starting at <tt>inOffset</tt>
	 * and that <tt>out</tt> is large enogh to hold an decrypted block starting
	 * at <tt>outOffset</tt>
	 * 
	 * @param in
	 *            byte[] containing the ciphertext to be decrypted starting at
	 *            inOffset
	 * @param inOffset
	 *            int index in the array in where the ciphertext block starts
	 * @param out
	 *            byte[] which will contain the plaintext startig at outOffset
	 * @param outOffset
	 *            int index in the array out where the plaintext block will
	 *            start
	 */
	protected void singleBlockDecrypt(byte[] in, int inOffset, byte[] out,
			int outOffset) {
		data[0] = bytesToShort(in, inOffset);
		data[1] = bytesToShort(in, inOffset + 2);
		data[2] = bytesToShort(in, inOffset + 4);
		data[3] = bytesToShort(in, inOffset + 6);
		j = 63;
		demix();
		demix();
		demix();
		demix();
		demix();
		demash();
		demix();
		demix();
		demix();
		demix();
		demix();
		demix();
		demash();
		demix();
		demix();
		demix();
		demix();
		demix();
		shortToBytes(out, outOffset, data[0]);
		shortToBytes(out, outOffset + 2, data[1]);
		shortToBytes(out, outOffset + 4, data[2]);
		shortToBytes(out, outOffset + 6, data[3]);
	}

	/**
	 * This method performs the descripted mix operation on data[] and modifies
	 * j
	 */
	private void mix() {
		data[0] += keyWord(j++) + (data[3] & data[2]) + (~data[3] & data[1]);
		data[0] = rotateLeft(data[0], 1);
		data[1] += keyWord(j++) + (data[0] & data[3]) + (~data[0] & data[2]);
		data[1] = rotateLeft(data[1], 2);
		data[2] += keyWord(j++) + (data[1] & data[0]) + (~data[1] & data[3]);
		data[2] = rotateLeft(data[2], 3);
		data[3] += keyWord(j++) + (data[2] & data[1]) + (~data[2] & data[0]);
		data[3] = rotateLeft(data[3], 5);
	}

	/**
	 * This method performs the descripted mash operation on data[]
	 */
	private void mash() {
		data[0] += keyWord(data[3] & 0x03f);
		data[1] += keyWord(data[0] & 0x03f);
		data[2] += keyWord(data[1] & 0x03f);
		data[3] += keyWord(data[2] & 0x03f);
	}

	/**
	 * This method performs the descripted inverse mix operation on data[] and
	 * modifies j
	 */
	private void demix() {
		data[3] = rotateRight(data[3], 5);
		data[3] = (short) (data[3] - keyWord(j--) - (data[2] & data[1]) - (~data[2] & data[0]));
		data[2] = rotateRight(data[2], 3);
		data[2] = (short) (data[2] - keyWord(j--) - (data[1] & data[0]) - (~data[1] & data[3]));
		data[1] = rotateRight(data[1], 2);
		data[1] = (short) (data[1] - keyWord(j--) - (data[0] & data[3]) - (~data[0] & data[2]));
		data[0] = rotateRight(data[0], 1);
		data[0] = (short) (data[0] - keyWord(j--) - (data[3] & data[2]) - (~data[3] & data[1]));
	}

	/**
	 * This method performs the descripted inverse mash operation on data[]
	 */
	private void demash() {
		data[3] = (short) (data[3] - keyWord(data[2] & 0x03f));
		data[2] = (short) (data[2] - keyWord(data[1] & 0x03f));
		data[1] = (short) (data[1] - keyWord(data[0] & 0x03f));
		data[0] = (short) (data[0] - keyWord(data[3] & 0x03f));
	}

	private short keyWord(int index) {
		return (short) ((key[index << 1] & 0xff) + (short) (key[(index << 1) + 1] << 8));
	}

	/**
	 * rotates left the given x by n digits
	 */
	private short rotateLeft(short x, int n) {
		return (short) ((x << n) | ((x & 0xffff) >>> (16 - n)));
	}

	/**
	 * rotates rigth the given x by n digits using wordsize bits
	 */
	private short rotateRight(short x, int n) {
		return (short) (((x & 0xffff) >>> n) | (x << (16 - n)));
	}

	/**
	 * converts a 2-byte short value into a byte array beginning at offset using
	 * little-endian
	 * 
	 * @param bytes
	 *            the byte array to hold the result
	 * @param offset
	 *            the integer offset into the byte array
	 * @param value
	 *            the long to convert
	 */
	private void shortToBytes(byte[] bytes, int offset, short value) {
		bytes[offset] = (byte) (value & 0xff);
		bytes[offset + 1] = (byte) ((value >>> 8) & 0xff);
	}

	/**
	 * converts a byte array beginning at offset into a 2-byte short value using
	 * little-endian
	 * 
	 * @param bytes
	 *            the byte array
	 * @param offset
	 *            the integer offset into the byte array
	 * @result short the resulting long
	 */
	private short bytesToShort(byte[] bytes, int offset) {
		short value = 0x0000;
		value |= bytes[offset] & 0x00ff;
		value |= (bytes[offset + 1] << 8) & 0xff00;
		return value;
	}
}
