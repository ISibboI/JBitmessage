/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.serpent;

import de.flexiprovider.api.BlockCipher;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.exceptions.NoSuchModeException;
import de.flexiprovider.api.keys.Key;
import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.api.keys.SecretKeySpec;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;

/**
 * This class implementes the Serpent block cipher. For more information, see <a
 * href="http://www.cl.cam.ac.uk/~rja14/serpent.html">http://www.cl.cam.ac.uk/~
 * rja14/serpent.html</a>. Serpent uses a block size of 128 bits. The key size
 * can be 128, 192, or 256 bits. Encryption/decryption takes 32 rounds.
 * 
 * @author Katja Rauch
 * @author Martin Döring
 */
public class Serpent extends BlockCipher {

	/**
	 * The algorithm name.
	 */
	public static final String ALG_NAME = "Serpent";

	/**
	 * The OID of Serpent (defined by the GNU project, see <a
	 * href="http://www.gnupg.org/oids.html"
	 * >http://www.gnupg.org/oids.html</a>).
	 */
	public static final String OID = "1.3.6.1.4.1.11591.13.2";

	/**
	 * Block size is 16 bytes (128 bits).
	 */
	private static final int blockSize = 16;

	// key size is a multiple of 32 and <= 256 (chosen by the constructor)
	private int keySize;

	// flag indicating whether the key size may be changed during
	// initialization
	private boolean keySizeIsMutable;

	/* key array */

	private int[] K = new int[132];

	/*
	 * Inner classes providing concrete implementations of Serpent with a
	 * variety of modes and key sizes.
	 */

	/**
	 * Serpent128_ECB
	 */
	public static class Serpent128_ECB extends Serpent {

		/**
		 * The OID of Serpent128_ECB (defined by the GNU project).
		 */
		public static final String OID = Serpent.OID + ".1";

		public Serpent128_ECB() {
			super("ECB", 4);
		}
	}

	/**
	 * Serpent128_CBC
	 */
	public static class Serpent128_CBC extends Serpent {

		/**
		 * The OID of Serpent128_CBC (defined by the GNU project).
		 */
		public static final String OID = Serpent.OID + ".2";

		public Serpent128_CBC() {
			super("CBC", 4);
		}
	}

	/**
	 * Serpent128_OFB
	 */
	public static class Serpent128_OFB extends Serpent {

		/**
		 * The OID of Serpent128_OFB (defined by the GNU project).
		 */
		public static final String OID = Serpent.OID + ".3";

		public Serpent128_OFB() {
			super("OFB", 4);
		}
	}

	/**
	 * Serpent128_CFB
	 */
	public static class Serpent128_CFB extends Serpent {

		/**
		 * The OID of Serpent128_CFB (defined by the GNU project).
		 */
		public static final String OID = Serpent.OID + ".4";

		public Serpent128_CFB() {
			super("CFB", 4);
		}
	}

	/**
	 * Serpent192_ECB
	 */
	public static class Serpent192_ECB extends Serpent {

		/**
		 * The OID of Serpent192_ECB (defined by the GNU project).
		 */
		public static final String OID = Serpent.OID + ".21";

		public Serpent192_ECB() {
			super("ECB", 6);
		}
	}

	/**
	 * Serpent192_CBC
	 */
	public static class Serpent192_CBC extends Serpent {

		/**
		 * The OID of Serpent192_CBC (defined by the GNU project).
		 */
		public static final String OID = Serpent.OID + ".22";

		public Serpent192_CBC() {
			super("CBC", 6);
		}
	}

	/**
	 * Serpent192_OFB
	 */
	public static class Serpent192_OFB extends Serpent {

		/**
		 * The OID of Serpent192_OFB (defined by the GNU project).
		 */
		public static final String OID = Serpent.OID + ".23";

		public Serpent192_OFB() {
			super("OFB", 6);
		}
	}

	/**
	 * Serpent192_CFB
	 */
	public static class Serpent192_CFB extends Serpent {

		/**
		 * The OID of Serpent192_CFB (defined by the GNU project).
		 */
		public static final String OID = Serpent.OID + ".24";

		public Serpent192_CFB() {
			super("CFB", 6);
		}
	}

	/**
	 * Serpent256_ECB
	 */
	public static class Serpent256_ECB extends Serpent {

		/**
		 * The OID of Serpent256_ECB (defined by the GNU project).
		 */
		public static final String OID = Serpent.OID + ".41";

		public Serpent256_ECB() {
			super("ECB", 8);
		}
	}

	/**
	 * Serpent256_CBC
	 */
	public static class Serpent256_CBC extends Serpent {

		/**
		 * The OID of Serpent256_CBC (defined by the GNU project).
		 */
		public static final String OID = Serpent.OID + ".42";

		public Serpent256_CBC() {
			super("CBC", 8);
		}
	}

	/**
	 * Serpent256_OFB
	 */
	public static class Serpent256_OFB extends Serpent {

		/**
		 * The OID of Serpent256_OFB (defined by the GNU project).
		 */
		public static final String OID = Serpent.OID + ".43";

		public Serpent256_OFB() {
			super("OFB", 8);
		}
	}

	/**
	 * Serpent256_CFB
	 */
	public static class Serpent256_CFB extends Serpent {

		/**
		 * The OID of Serpent256_CFB (defined by the GNU project).
		 */
		public static final String OID = Serpent.OID + ".44";

		public Serpent256_CFB() {
			super("CFB", 8);
		}
	}

	/**
	 * Constructor.
	 * 
	 * @param modeName
	 *            the mode to use
	 * @param keySize
	 *            the key size in words
	 */
	protected Serpent(String modeName, int keySize) {

		// set the key size
		this.keySize = keySize;
		// changing the key size is disallowed
		keySizeIsMutable = false;

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
	public Serpent() {
		// allow setting of the key size during initialization
		keySizeIsMutable = true;
	}

	/**
	 * @return the name of this cipher
	 */
	public String getName() {
		return ALG_NAME;
	}

	/**
	 * Return the key size of the given key object. Checks whether the key
	 * object is an instance of <tt>SerpentKey</tt> or <tt>SecretKeySpec</tt>
	 * and whether the key size is within the specified range for Serpent. For
	 * the AES submission, the key size was fixed to be either 128, 192, or 256
	 * bits, however shorter keys are allowed and appropriately padded as long
	 * as the key size is a multiple of 32 bits.
	 * 
	 * @param key
	 *            the key object
	 * @return the key size of the given key object.
	 * @throws InvalidKeyException
	 *             if key is invalid.
	 */
	public int getKeySize(Key key) throws InvalidKeyException {
		if (!((key instanceof SerpentKey) || (key instanceof SecretKeySpec))) {
			throw new InvalidKeyException("not a Serpent Key");
		}

		int keySize = key.getEncoded().length;

		if ((keySize > 32) || ((keySize & 0x03) != 0)) {
			throw new InvalidKeyException("invalid key size");
		}
		return keySize;
	}

	/**
	 * This method returns the blocksize the algorithm uses. It will be called
	 * by the padding scheme.
	 * 
	 * @return the used blocksize in <B>bytes</B>
	 */
	public int getCipherBlockSize() {
		return blockSize;
	}

	/**
	 * Initialize the block cipher with a secret key for data encryption. The
	 * algorithm parameters are not used.
	 * 
	 * @param key
	 *            - the SecretKey which has to be used to decrypt data.
	 * @param params
	 *            - algorithmParameterSpec, not used for here
	 * @throws InvalidKeyException
	 *             if the given key is inappropriate for initialising this
	 *             cipher.
	 */
	protected void initCipherEncrypt(SecretKey key,
			AlgorithmParameterSpec params) throws InvalidKeyException {
		if (!(key instanceof SerpentKey)) {
			throw new InvalidKeyException("not a Serpent Key");
		}
		byte[] keyBytes = key.getEncoded();
		if (keySizeIsMutable) {
			keySize = keyBytes.length << 3;
		} else if (keyBytes.length != keySize >> 3) {
			throw new InvalidKeyException(
					"key size does not match specified length.");
		}
		keyExpansion(keyBytes);
	}

	/**
	 * Initialize the block cipher with a secret key for data decryption. The
	 * algorithm parameters are not used.
	 * 
	 * @param key
	 *            - the SecretKey which has to be used to decrypt data.
	 * @param params
	 *            - algorithmParameterSpec, not used for here
	 * @throws InvalidKeyException
	 *             if the given key is inappropriate for initialising this
	 *             cipher.
	 */
	protected void initCipherDecrypt(SecretKey key,
			AlgorithmParameterSpec params) throws InvalidKeyException {
		initCipherEncrypt(key, params);
	}

	/**
	 * This method implements the Serpent key expansion.
	 * 
	 * @param key
	 *            An array of bytes contaning the key data
	 */
	private void keyExpansion(byte[] key) {

		int i, j, n, tmp;
		int R = 0x9E3779B9;
		int offset = 0;
		int tmp1;
		int t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15;

		n = key.length / 4;

		/* converting input bytes to INT */

		for (i = 0; i < n; i++) {
			K[i] = (key[offset++] & 255) | ((key[offset++] & 255) << 8)
					| ((key[offset++] & 255) << 16)
					| ((key[offset++] & 255) << 24);
		}

		/* expanding the key to an int [16] key array */

		if (n < 8) {
			K[i++] = 1;
		}
		while (i < 8) {
			K[i++] = 0;
		}
		for (i = 8; i < 16; i++) {
			tmp = K[i - 8] ^ K[i - 5] ^ K[i - 3] ^ K[i - 1] ^ R ^ (i - 8);
			K[i] = (tmp << 11) | (tmp >>> 21);
		}
		for (i = 8, j = 0; i < 16; i++, j++) {
			K[j] = K[i];
		}
		for (i = 8; i < 132; i++) {
			tmp = K[i - 8] ^ K[i - 5] ^ K[i - 3] ^ K[i - 1] ^ R ^ i;
			K[i] = (tmp << 11) | (tmp >>> 21);
		}

		/* expanding the key to an int [132] key array */

		for (i = 0; i < 4; i++) {

			/* Gladmans boolean S[3][i] function */

			j = i << 5;
			t1 = K[j] ^ K[j + 1];
			t2 = K[j] & K[j + 2];
			t3 = K[j] | K[j + 3];
			t4 = K[j + 2] ^ K[j + 3];
			t5 = t1 & t3;
			t6 = t2 | t5;
			K[j + 2] = t4 ^ t6;
			t8 = K[j + 1] ^ t3;
			t9 = t6 ^ t8;
			t10 = t4 & t9;
			K[j] = t1 ^ t10;
			t12 = K[j + 2] & K[j];
			tmp = K[j + 1];
			K[j + 1] = t9 ^ t12;
			t14 = tmp | K[j + 3];
			t15 = t4 ^ t12;
			K[j + 3] = t14 ^ t15;

			/* Gladmans boolean S[2][i] function */

			j = j + 4;
			t1 = ~K[j];
			t2 = K[j + 1] ^ K[j + 3];
			t3 = K[j + 2] & t1;
			tmp = K[j];
			K[j] = t2 ^ t3;
			t5 = K[j + 2] ^ t1;
			t6 = K[j + 2] ^ K[j];
			t7 = K[j + 1] & t6;
			tmp1 = K[j + 3];
			K[j + 3] = t5 ^ t7;
			t9 = tmp1 | t7;
			t10 = K[j] | t5;
			t11 = t9 & t10;
			K[j + 2] = tmp ^ t11;
			t13 = tmp1 | t1;
			t14 = t2 ^ K[j + 3];
			t15 = K[j + 2] ^ t13;
			K[j + 1] = t14 ^ t15;

			/* Gladmans boolean S[1][i] function */

			j = j + 4;
			t1 = ~K[j];
			t2 = K[j + 1] ^ t1;
			t3 = K[j] | t2;
			t4 = K[j + 3] | t2;
			t5 = K[j + 2] ^ t3;
			K[j + 2] = K[j + 3] ^ t5;
			t7 = K[j + 1] ^ t4;
			t8 = t2 ^ K[j + 2];
			t9 = t5 & t7;
			K[j + 3] = t8 ^ t9;
			t11 = t5 ^ t7;
			K[j + 1] = K[j + 3] ^ t11;
			t13 = t11 & t8;
			K[j] = t5 ^ t13;

			/* Gladmans boolean S[0][i] function */

			j = j + 4;
			t1 = K[j] ^ K[j + 3];
			t2 = K[j] & K[j + 3];
			t3 = K[j + 2] ^ t1;
			t4 = K[j + 1] ^ t3;
			K[j + 3] = t2 ^ t4;
			t6 = K[j + 1] & t1;
			t7 = K[j] ^ t6;
			t8 = K[j + 2] | t7;
			K[j + 2] = t4 ^ t8;
			t10 = ~t3;
			t11 = t3 ^ t7;
			t12 = K[j + 3] & t11;
			K[j + 1] = t10 ^ t12;
			t14 = ~t7;
			K[j] = t12 ^ t14;

			/* Gladmans boolean S[7][i] function */

			j = j + 4;
			t1 = K[j + 1] ^ K[j + 2];
			t2 = K[j + 2] & t1;
			t3 = K[j + 3] ^ t2;
			t4 = K[j] ^ t3;
			t5 = K[j + 3] | t1;
			t6 = t4 & t5;
			K[j + 1] = K[j + 1] ^ t6;
			t8 = t3 | K[j + 1];
			t9 = K[j] & t4;
			K[j + 3] = t1 ^ t9;
			t11 = t4 ^ t8;
			t12 = K[j + 3] & t11;
			K[j + 2] = t3 ^ t12;
			t14 = ~t11;
			t15 = K[j + 2] & K[j + 3];
			K[j] = t14 ^ t15;

			/* Gladmans boolean S[6][i] function */

			j = j + 4;
			t1 = ~K[j];
			t2 = K[j] ^ K[j + 3];
			t3 = K[j + 1] ^ t2;
			t4 = t1 | t2;
			t5 = K[j + 2] ^ t4;
			K[j + 1] = K[j + 1] ^ t5;
			t7 = t2 | K[j + 1];
			t8 = K[j + 3] ^ t7;
			t9 = t5 & t8;
			K[j + 2] = t3 ^ t9;
			t11 = t5 ^ t8;
			K[j] = K[j + 2] ^ t11;
			t13 = ~t5;
			t14 = t3 & t11;
			K[j + 3] = t13 ^ t14;

			/* Gladmans boolean S[5][i] function */

			j = j + 4;
			t1 = ~K[j];
			t2 = K[j] ^ K[j + 1];
			t3 = K[j] ^ K[j + 3];
			t4 = K[j + 2] ^ t1;
			t5 = t2 | t3;
			K[j] = t4 ^ t5;
			t7 = K[j + 3] & K[j];
			t8 = t2 ^ K[j];
			tmp = K[j + 1];
			K[j + 1] = t7 ^ t8;
			t10 = t1 | K[j];
			t11 = t2 | t7;
			t12 = t3 ^ t10;
			K[j + 2] = t11 ^ t12;
			t14 = tmp ^ t7;
			t15 = K[j + 1] & t12;
			K[j + 3] = t14 ^ t15;

			/* Gladmans boolean S[4][i] function */

			j = j + 4;
			t1 = K[j] ^ K[j + 3];
			t2 = K[j + 3] & t1;
			t3 = K[j + 2] ^ t2;
			t4 = K[j + 1] | t3;
			K[j + 3] = t1 ^ t4;
			t6 = ~K[j + 1];
			t7 = t1 | t6;
			tmp = K[j];
			K[j] = t3 ^ t7;
			t9 = tmp & K[j];
			t10 = t1 ^ t6;
			t11 = t4 & t10;
			K[j + 2] = t9 ^ t11;
			t13 = tmp ^ t3;
			t14 = t10 & K[j + 2];
			K[j + 1] = t13 ^ t14;
		}

		/* Gladmans boolean S[3][i] function */

		j = 128;
		t1 = K[j] ^ K[j + 1];
		t2 = K[j] & K[j + 2];
		t3 = K[j] | K[j + 3];
		t4 = K[j + 2] ^ K[j + 3];
		t5 = t1 & t3;
		t6 = t2 | t5;
		K[j + 2] = t4 ^ t6;
		t8 = K[j + 1] ^ t3;
		t9 = t6 ^ t8;
		t10 = t4 & t9;
		K[j] = t1 ^ t10;
		t12 = K[j + 2] & K[j];
		tmp = K[j + 1];
		K[j + 1] = t9 ^ t12;
		t14 = tmp | K[j + 3];
		t15 = t4 ^ t12;
		K[j + 3] = t14 ^ t15;
	}

	/**
	 * This method encrypts a single block of data. The array <TT>in</TT> must
	 * contain a whole block starting at <TT>inOffset</TT> and <TT>out</TT> must
	 * be large enough to hold an encrypted block starting at <TT>outOffset</TT>
	 * .
	 * 
	 * @param in
	 *            array of bytes containing the plaintext to be encrypted
	 * @param inoffset
	 *            index in array in, where the plaintext block starts
	 * @param out
	 *            array of bytes which will contain the ciphertext starting at
	 *            outOffset
	 * @param outoffset
	 *            index in array out, where the ciphertext block will start
	 */

	protected void singleBlockEncrypt(byte[] in, int inoffset, byte[] out,
			int outoffset) {
		int i, j;
		int d0, d1, d2, d3;
		int tmp, tmp1;
		int t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15;

		/* converting input bytes to INT */

		d0 = ((in[inoffset++]) & 255) | (((in[inoffset++]) & 255) << 8)
				| (((in[inoffset++]) & 255) << 16)
				| (((in[inoffset++]) & 255) << 24);
		d1 = ((in[inoffset++]) & 255) | (((in[inoffset++]) & 255) << 8)
				| (((in[inoffset++]) & 255) << 16)
				| (((in[inoffset++]) & 255) << 24);
		d2 = ((in[inoffset++]) & 255) | (((in[inoffset++]) & 255) << 8)
				| (((in[inoffset++]) & 255) << 16)
				| (((in[inoffset++]) & 255) << 24);
		d3 = ((in[inoffset++]) & 255) | (((in[inoffset++]) & 255) << 8)
				| (((in[inoffset++]) & 255) << 16)
				| (((in[inoffset++]) & 255) << 24);

		/* 32 transformation rounds */

		for (i = 0; i < 4; i++) {
			j = i << 5;

			/* XOR keys and data */

			d0 = d0 ^ K[j++];
			d1 = d1 ^ K[j++];
			d2 = d2 ^ K[j++];
			d3 = d3 ^ K[j++];

			/* Gladmans boolean S[0][i] function */

			t1 = d0 ^ d3;
			t2 = d0 & d3;
			t3 = d2 ^ t1;
			t4 = d1 ^ t3;
			d3 = t2 ^ t4;
			t6 = d1 & t1;
			t7 = d0 ^ t6;
			t8 = d2 | t7;
			d2 = t4 ^ t8;
			t10 = ~t3;
			t11 = t3 ^ t7;
			t12 = d3 & t11;
			d1 = t10 ^ t12;
			t14 = ~t7;
			d0 = t12 ^ t14;

			/* linear transformation */

			d0 = (d0 << 13) | (d0 >>> 19);
			d2 = (d2 << 3) | (d2 >>> 29);
			d1 = d1 ^ d0 ^ d2;
			d3 = d3 ^ d2 ^ (d0 << 3);
			d1 = (d1 << 1) | (d1 >>> 31);
			d3 = (d3 << 7) | (d3 >>> 25);
			d0 = d0 ^ d1 ^ d3;
			d2 = d2 ^ d3 ^ (d1 << 7);
			d0 = (d0 << 5) | (d0 >>> 27);
			d2 = (d2 << 22) | (d2 >>> 10);

			/* XOR keys and data */

			d0 = d0 ^ K[j++];
			d1 = d1 ^ K[j++];
			d2 = d2 ^ K[j++];
			d3 = d3 ^ K[j++];

			/* Gladmans boolean S[1][i] function */

			t1 = ~d0;
			t2 = d1 ^ t1;
			t3 = d0 | t2;
			t4 = d3 | t2;
			t5 = d2 ^ t3;
			d2 = d3 ^ t5;
			t7 = d1 ^ t4;
			t8 = t2 ^ d2;
			t9 = t5 & t7;
			d3 = t8 ^ t9;
			t11 = t5 ^ t7;
			d1 = d3 ^ t11;
			t13 = t11 & t8;
			d0 = t5 ^ t13;

			/* linear transformation */

			d0 = (d0 << 13) | (d0 >>> 19);
			d2 = (d2 << 3) | (d2 >>> 29);
			d1 = d1 ^ d0 ^ d2;
			d3 = d3 ^ d2 ^ (d0 << 3);
			d1 = (d1 << 1) | (d1 >>> 31);
			d3 = (d3 << 7) | (d3 >>> 25);
			d0 = d0 ^ d1 ^ d3;
			d2 = d2 ^ d3 ^ (d1 << 7);
			d0 = (d0 << 5) | (d0 >>> 27);
			d2 = (d2 << 22) | (d2 >>> 10);

			/* XOR keys and data */

			d0 = d0 ^ K[j++];
			d1 = d1 ^ K[j++];
			d2 = d2 ^ K[j++];
			d3 = d3 ^ K[j++];

			/* Gladmans boolean S[2][i] function */

			t1 = ~d0;
			t2 = d1 ^ d3;
			t3 = d2 & t1;
			tmp = d0;
			d0 = t2 ^ t3;
			t5 = d2 ^ t1;
			t6 = d2 ^ d0;
			t7 = d1 & t6;
			tmp1 = d3;
			d3 = t5 ^ t7;
			t9 = tmp1 | t7;
			t10 = d0 | t5;
			t11 = t9 & t10;
			d2 = tmp ^ t11;
			t13 = tmp1 | t1;
			t14 = t2 ^ d3;
			t15 = d2 ^ t13;
			d1 = t14 ^ t15;

			/* linear transformation */

			d0 = (d0 << 13) | (d0 >>> 19);
			d2 = (d2 << 3) | (d2 >>> 29);
			d1 = d1 ^ d0 ^ d2;
			d3 = d3 ^ d2 ^ (d0 << 3);
			d1 = (d1 << 1) | (d1 >>> 31);
			d3 = (d3 << 7) | (d3 >>> 25);
			d0 = d0 ^ d1 ^ d3;
			d2 = d2 ^ d3 ^ (d1 << 7);
			d0 = (d0 << 5) | (d0 >>> 27);
			d2 = (d2 << 22) | (d2 >>> 10);

			/* XOR keys and data */

			d0 = d0 ^ K[j++];
			d1 = d1 ^ K[j++];
			d2 = d2 ^ K[j++];
			d3 = d3 ^ K[j++];

			/* Gladmans boolean S[3][i] function */

			t1 = d0 ^ d1;
			t2 = d0 & d2;
			t3 = d0 | d3;
			t4 = d2 ^ d3;
			t5 = t1 & t3;
			t6 = t2 | t5;
			d2 = t4 ^ t6;
			t8 = d1 ^ t3;
			t9 = t6 ^ t8;
			t10 = t4 & t9;
			d0 = t1 ^ t10;
			t12 = d2 & d0;
			tmp = d1;
			d1 = t9 ^ t12;
			t14 = tmp | d3;
			t15 = t4 ^ t12;
			d3 = t14 ^ t15;

			/* linear transformation */

			d0 = (d0 << 13) | (d0 >>> 19);
			d2 = (d2 << 3) | (d2 >>> 29);
			d1 = d1 ^ d0 ^ d2;
			d3 = d3 ^ d2 ^ (d0 << 3);
			d1 = (d1 << 1) | (d1 >>> 31);
			d3 = (d3 << 7) | (d3 >>> 25);
			d0 = d0 ^ d1 ^ d3;
			d2 = d2 ^ d3 ^ (d1 << 7);
			d0 = (d0 << 5) | (d0 >>> 27);
			d2 = (d2 << 22) | (d2 >>> 10);

			/* XOR keys and data */

			d0 = d0 ^ K[j++];
			d1 = d1 ^ K[j++];
			d2 = d2 ^ K[j++];
			d3 = d3 ^ K[j++];

			/* Gladmans boolean S[4][i] function */

			t1 = d0 ^ d3;
			t2 = d3 & t1;
			t3 = d2 ^ t2;
			t4 = d1 | t3;
			d3 = t1 ^ t4;
			t6 = ~d1;
			t7 = t1 | t6;
			tmp = d0;
			d0 = t3 ^ t7;
			t9 = tmp & d0;
			t10 = t1 ^ t6;
			t11 = t4 & t10;
			d2 = t9 ^ t11;
			t13 = tmp ^ t3;
			t14 = t10 & d2;
			d1 = t13 ^ t14;

			/* linear transformation */

			d0 = (d0 << 13) | (d0 >>> 19);
			d2 = (d2 << 3) | (d2 >>> 29);
			d1 = d1 ^ d0 ^ d2;
			d3 = d3 ^ d2 ^ (d0 << 3);
			d1 = (d1 << 1) | (d1 >>> 31);
			d3 = (d3 << 7) | (d3 >>> 25);
			d0 = d0 ^ d1 ^ d3;
			d2 = d2 ^ d3 ^ (d1 << 7);
			d0 = (d0 << 5) | (d0 >>> 27);
			d2 = (d2 << 22) | (d2 >>> 10);

			/* XOR keys and data */

			d0 = d0 ^ K[j++];
			d1 = d1 ^ K[j++];
			d2 = d2 ^ K[j++];
			d3 = d3 ^ K[j++];

			/* Gladmans boolean S[5][i] function */

			t1 = ~d0;
			t2 = d0 ^ d1;
			t3 = d0 ^ d3;
			t4 = d2 ^ t1;
			t5 = t2 | t3;
			d0 = t4 ^ t5;
			t7 = d3 & d0;
			t8 = t2 ^ d0;
			tmp = d1;
			d1 = t7 ^ t8;
			t10 = t1 | d0;
			t11 = t2 | t7;
			t12 = t3 ^ t10;
			d2 = t11 ^ t12;
			t14 = tmp ^ t7;
			t15 = d1 & t12;
			d3 = t14 ^ t15;

			/* linear transformation */

			d0 = (d0 << 13) | (d0 >>> 19);
			d2 = (d2 << 3) | (d2 >>> 29);
			d1 = d1 ^ d0 ^ d2;
			d3 = d3 ^ d2 ^ (d0 << 3);
			d1 = (d1 << 1) | (d1 >>> 31);
			d3 = (d3 << 7) | (d3 >>> 25);
			d0 = d0 ^ d1 ^ d3;
			d2 = d2 ^ d3 ^ (d1 << 7);
			d0 = (d0 << 5) | (d0 >>> 27);
			d2 = (d2 << 22) | (d2 >>> 10);

			/* XOR keys and data */

			d0 = d0 ^ K[j++];
			d1 = d1 ^ K[j++];
			d2 = d2 ^ K[j++];
			d3 = d3 ^ K[j++];

			/* Gladmans boolean S[6][i] function */

			t1 = ~d0;
			t2 = d0 ^ d3;
			t3 = d1 ^ t2;
			t4 = t1 | t2;
			t5 = d2 ^ t4;
			d1 = d1 ^ t5;
			t7 = t2 | d1;
			t8 = d3 ^ t7;
			t9 = t5 & t8;
			d2 = t3 ^ t9;
			t11 = t5 ^ t8;
			d0 = d2 ^ t11;
			t13 = ~t5;
			t14 = t3 & t11;
			d3 = t13 ^ t14;

			/* linear transformation */

			d0 = (d0 << 13) | (d0 >>> 19);
			d2 = (d2 << 3) | (d2 >>> 29);
			d1 = d1 ^ d0 ^ d2;
			d3 = d3 ^ d2 ^ (d0 << 3);
			d1 = (d1 << 1) | (d1 >>> 31);
			d3 = (d3 << 7) | (d3 >>> 25);
			d0 = d0 ^ d1 ^ d3;
			d2 = d2 ^ d3 ^ (d1 << 7);
			d0 = (d0 << 5) | (d0 >>> 27);
			d2 = (d2 << 22) | (d2 >>> 10);

			/* XOR keys and data */

			d0 = d0 ^ K[j++];
			d1 = d1 ^ K[j++];
			d2 = d2 ^ K[j++];
			d3 = d3 ^ K[j++];

			/* Gladmans boolean S[7][i] function */

			t1 = d1 ^ d2;
			t2 = d2 & t1;
			t3 = d3 ^ t2;
			t4 = d0 ^ t3;
			t5 = d3 | t1;
			t6 = t4 & t5;
			d1 = d1 ^ t6;
			t8 = t3 | d1;
			t9 = d0 & t4;
			d3 = t1 ^ t9;
			t11 = t4 ^ t8;
			t12 = d3 & t11;
			d2 = t3 ^ t12;
			t14 = ~t11;
			t15 = d2 & d3;
			d0 = t14 ^ t15;

			/* excluding transformation in the last round */

			if (i < 3) {
				d0 = (d0 << 13) | (d0 >>> 19);
				d2 = (d2 << 3) | (d2 >>> 29);
				d1 = d1 ^ d0 ^ d2;
				d3 = d3 ^ d2 ^ (d0 << 3);
				d1 = (d1 << 1) | (d1 >>> 31);
				d3 = (d3 << 7) | (d3 >>> 25);
				d0 = d0 ^ d1 ^ d3;
				d2 = d2 ^ d3 ^ (d1 << 7);
				d0 = (d0 << 5) | (d0 >>> 27);
				d2 = (d2 << 22) | (d2 >>> 10);
			}
		}

		/* XOR keys and data */

		d0 = d0 ^ K[128];
		d1 = d1 ^ K[129];
		d2 = d2 ^ K[130];
		d3 = d3 ^ K[131];

		/* converting INT to output bytes */

		out[outoffset++] = (byte) d0;
		out[outoffset++] = (byte) (d0 >> 8);
		out[outoffset++] = (byte) (d0 >> 16);
		out[outoffset++] = (byte) (d0 >> 24);
		out[outoffset++] = (byte) d1;
		out[outoffset++] = (byte) (d1 >> 8);
		out[outoffset++] = (byte) (d1 >> 16);
		out[outoffset++] = (byte) (d1 >> 24);
		out[outoffset++] = (byte) d2;
		out[outoffset++] = (byte) (d2 >> 8);
		out[outoffset++] = (byte) (d2 >> 16);
		out[outoffset++] = (byte) (d2 >> 24);
		out[outoffset++] = (byte) d3;
		out[outoffset++] = (byte) (d3 >> 8);
		out[outoffset++] = (byte) (d3 >> 16);
		out[outoffset++] = (byte) (d3 >> 24);
	}

	/**
	 * This method decrypts a single block of data. The array <TT>in</TT> must
	 * contain a whole block starting at <TT>inOffset</TT> and <TT>out</TT> must
	 * be large enough to hold an encrypted block starting at <TT>outOffset</TT>
	 * .
	 * 
	 * @param in
	 *            array of bytes containig the ciphertext to be decrypted
	 * @param inoffset
	 *            index in array in, where the ciphertext block starts
	 * @param out
	 *            array of bytes which will contain the plaintext starting at
	 *            outOffset
	 * @param outoffset
	 *            index in array out, where the plaintext block will start
	 */

	protected void singleBlockDecrypt(byte[] in, int inoffset, byte[] out,
			int outoffset) {
		int i, j;
		int d0, d1, d2, d3;
		int tmp, tmp1;
		int t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15, t16;

		/* converting input bytes to INT */

		d0 = ((in[inoffset++]) & 255) | (((in[inoffset++]) & 255) << 8)
				| (((in[inoffset++]) & 255) << 16)
				| (((in[inoffset++]) & 255) << 24);
		d1 = ((in[inoffset++]) & 255) | (((in[inoffset++]) & 255) << 8)
				| (((in[inoffset++]) & 255) << 16)
				| (((in[inoffset++]) & 255) << 24);
		d2 = ((in[inoffset++]) & 255) | (((in[inoffset++]) & 255) << 8)
				| (((in[inoffset++]) & 255) << 16)
				| (((in[inoffset++]) & 255) << 24);
		d3 = ((in[inoffset++]) & 255) | (((in[inoffset++]) & 255) << 8)
				| (((in[inoffset++]) & 255) << 16)
				| (((in[inoffset++]) & 255) << 24);

		/* XOR keys and data */

		d0 = d0 ^ K[128];
		d1 = d1 ^ K[129];
		d2 = d2 ^ K[130];
		d3 = d3 ^ K[131];

		for (i = 3; i >= 0; i--) {
			j = (i << 5) + 28;

			/* excluding transformation in the last round */

			if (i < 3) {
				d2 = (d2 << 10) | (d2 >>> 22);
				d0 = (d0 << 27) | (d0 >>> 5);
				d2 = d2 ^ d3 ^ (d1 << 7);
				d0 = d0 ^ d1 ^ d3;
				d3 = (d3 << 25) | (d3 >>> 7);
				d1 = (d1 << 31) | (d1 >>> 1);
				d3 = d3 ^ d2 ^ (d0 << 3);
				d1 = d1 ^ d0 ^ d2;
				d2 = (d2 << 29) | (d2 >>> 3);
				d0 = (d0 << 19) | (d0 >>> 13);
			}

			/* Gladmans boolean Si[7][i] function */

			t1 = d0 & d1;
			t2 = d0 | d1;
			t3 = d2 | t1;
			t4 = d3 & t2;
			tmp = d3;
			d3 = t3 ^ t4;
			t6 = ~tmp;
			t7 = d1 ^ t4;
			t8 = d3 ^ t6;
			t9 = t7 | t8;
			d1 = d0 ^ t9;
			t11 = d2 ^ t7;
			t12 = tmp | d1;
			tmp = d0;
			d0 = t11 ^ t12;
			t14 = tmp & d3;
			t15 = t3 ^ d1;
			t16 = d0 ^ t14;
			d2 = t15 ^ t16;

			/* XOR keys and data */

			d0 = d0 ^ K[j++];
			d1 = d1 ^ K[j++];
			d2 = d2 ^ K[j++];
			d3 = d3 ^ K[j];

			j = (i << 5) + 24;

			/* linear transformation */

			d2 = (d2 << 10) | (d2 >>> 22);
			d0 = (d0 << 27) | (d0 >>> 5);
			d2 = d2 ^ d3 ^ (d1 << 7);
			d0 = d0 ^ d1 ^ d3;
			d3 = (d3 << 25) | (d3 >>> 7);
			d1 = (d1 << 31) | (d1 >>> 1);
			d3 = d3 ^ d2 ^ (d0 << 3);
			d1 = d1 ^ d0 ^ d2;
			d2 = (d2 << 29) | (d2 >>> 3);
			d0 = (d0 << 19) | (d0 >>> 13);

			/* Gladmans boolean Si[6][i] function */

			t1 = ~d0;
			t2 = d0 ^ d1;
			t3 = d2 ^ t2;
			t4 = d2 | t1;
			t5 = d3 ^ t4;
			tmp = d1;
			d1 = t3 ^ t5;
			t7 = t3 & t5;
			t8 = t2 ^ t7;
			t9 = tmp | t8;
			tmp1 = d3;
			d3 = t5 ^ t9;
			t11 = tmp | d3;
			d0 = t8 ^ t11;
			t13 = tmp1 & t1;
			t14 = t3 ^ t11;
			d2 = t13 ^ t14;

			/* XOR keys and data */

			d0 = d0 ^ K[j++];
			d1 = d1 ^ K[j++];
			d2 = d2 ^ K[j++];
			d3 = d3 ^ K[j];

			j = (i << 5) + 20;

			/* linear transformation */

			d2 = (d2 << 10) | (d2 >>> 22);
			d0 = (d0 << 27) | (d0 >>> 5);
			d2 = d2 ^ d3 ^ (d1 << 7);
			d0 = d0 ^ d1 ^ d3;
			d3 = (d3 << 25) | (d3 >>> 7);
			d1 = (d1 << 31) | (d1 >>> 1);
			d3 = d3 ^ d2 ^ (d0 << 3);
			d1 = d1 ^ d0 ^ d2;
			d2 = (d2 << 29) | (d2 >>> 3);
			d0 = (d0 << 19) | (d0 >>> 13);

			/* Gladmans boolean Si[5][i] function */

			t1 = ~d2;
			t2 = d1 & t1;
			t3 = d3 ^ t2;
			t4 = d0 & t3;
			t5 = d1 ^ t1;
			tmp = d3;
			d3 = t4 ^ t5;
			t7 = d1 | d3;
			t8 = d0 & t7;
			tmp1 = d1;
			d1 = t3 ^ t8;
			t10 = d0 | tmp;
			t11 = t1 ^ t7;
			tmp = d0;
			d0 = t10 ^ t11;
			t13 = tmp ^ d2;
			t14 = tmp1 & t10;
			t15 = t4 | t13;
			d2 = t14 ^ t15;

			/* XOR keys and data */

			d0 = d0 ^ K[j++];
			d1 = d1 ^ K[j++];
			d2 = d2 ^ K[j++];
			d3 = d3 ^ K[j];

			j = (i << 5) + 16;

			/* linear transformation */

			d2 = (d2 << 10) | (d2 >>> 22);
			d0 = (d0 << 27) | (d0 >>> 5);
			d2 = d2 ^ d3 ^ (d1 << 7);
			d0 = d0 ^ d1 ^ d3;
			d3 = (d3 << 25) | (d3 >>> 7);
			d1 = (d1 << 31) | (d1 >>> 1);
			d3 = d3 ^ d2 ^ (d0 << 3);
			d1 = d1 ^ d0 ^ d2;
			d2 = (d2 << 29) | (d2 >>> 3);
			d0 = (d0 << 19) | (d0 >>> 13);

			/* Gladmans boolean Si[4][i] function */

			t1 = d2 | d3;
			t2 = d0 & t1;
			t3 = d1 ^ t2;
			t4 = d0 & t3;
			t5 = d2 ^ t4;
			d1 = d3 ^ t5;
			t7 = ~d0;
			t8 = t5 & d1;
			tmp1 = d3;
			d3 = t3 ^ t8;
			t10 = d1 | t7;
			t11 = tmp1 ^ t10;
			d0 = d3 ^ t11;
			t13 = t3 & t11;
			t14 = d1 ^ t7;
			d2 = t13 ^ t14;

			/* XOR keys and data */

			d0 = d0 ^ K[j++];
			d1 = d1 ^ K[j++];
			d2 = d2 ^ K[j++];
			d3 = d3 ^ K[j];

			j = (i << 5) + 12;

			/* linear transformation */

			d2 = (d2 << 10) | (d2 >>> 22);
			d0 = (d0 << 27) | (d0 >>> 5);
			d2 = d2 ^ d3 ^ (d1 << 7);
			d0 = d0 ^ d1 ^ d3;
			d3 = (d3 << 25) | (d3 >>> 7);
			d1 = (d1 << 31) | (d1 >>> 1);
			d3 = d3 ^ d2 ^ (d0 << 3);
			d1 = d1 ^ d0 ^ d2;
			d2 = (d2 << 29) | (d2 >>> 3);
			d0 = (d0 << 19) | (d0 >>> 13);

			/* Gladmans boolean Si[3][i] function */

			t1 = d0 | d1;
			t2 = d1 ^ d2;
			t3 = d1 & t2;
			t4 = d0 ^ t3;
			t5 = d2 ^ t4;
			t6 = d3 | t4;
			d0 = t2 ^ t6;
			t8 = t2 | t6;
			t9 = d3 ^ t8;
			d2 = t5 ^ t9;
			t11 = t1 ^ t9;
			t12 = d0 & t11;
			d3 = t4 ^ t12;
			t14 = d0 ^ t11;
			d1 = d3 ^ t14;

			/* XOR keys and data */

			d0 = d0 ^ K[j++];
			d1 = d1 ^ K[j++];
			d2 = d2 ^ K[j++];
			d3 = d3 ^ K[j];

			j = (i << 5) + 8;

			/* linear transformation */

			d2 = (d2 << 10) | (d2 >>> 22);
			d0 = (d0 << 27) | (d0 >>> 5);
			d2 = d2 ^ d3 ^ (d1 << 7);
			d0 = d0 ^ d1 ^ d3;
			d3 = (d3 << 25) | (d3 >>> 7);
			d1 = (d1 << 31) | (d1 >>> 1);
			d3 = d3 ^ d2 ^ (d0 << 3);
			d1 = d1 ^ d0 ^ d2;
			d2 = (d2 << 29) | (d2 >>> 3);
			d0 = (d0 << 19) | (d0 >>> 13);

			/* Gladmans boolean Si[2][i] function */

			t1 = d1 ^ d3;
			t2 = ~t1;
			t3 = d0 ^ d2;
			t4 = d2 ^ t1;
			t5 = d1 & t4;
			tmp = d0;
			d0 = t3 ^ t5;
			t7 = tmp | t2;
			t8 = d3 ^ t7;
			t9 = t3 | t8;
			tmp = d3;
			d3 = t1 ^ t9;
			t11 = ~t4;
			t12 = d0 | d3;
			d1 = t11 ^ t12;
			t14 = tmp & t11;
			t15 = t3 ^ t12;
			d2 = t14 ^ t15;

			/* XOR keys and data */

			d0 = d0 ^ K[j++];
			d1 = d1 ^ K[j++];
			d2 = d2 ^ K[j++];
			d3 = d3 ^ K[j];

			j = (i << 5) + 4;

			/* linear transformation */

			d2 = (d2 << 10) | (d2 >>> 22);
			d0 = (d0 << 27) | (d0 >>> 5);
			d2 = d2 ^ d3 ^ (d1 << 7);
			d0 = d0 ^ d1 ^ d3;
			d3 = (d3 << 25) | (d3 >>> 7);
			d1 = (d1 << 31) | (d1 >>> 1);
			d3 = d3 ^ d2 ^ (d0 << 3);
			d1 = d1 ^ d0 ^ d2;
			d2 = (d2 << 29) | (d2 >>> 3);
			d0 = (d0 << 19) | (d0 >>> 13);

			/* Gladmans boolean Si[1][i] function */

			t1 = d1 ^ d3;
			t2 = d1 & t1;
			t3 = d0 ^ t2;
			t4 = t1 ^ t3;
			d3 = d2 ^ t4;
			t6 = t1 & t3;
			t7 = d1 ^ t6;
			t8 = d3 | t7;
			d1 = t3 ^ t8;
			t10 = ~d1;
			t11 = d3 ^ t7;
			d0 = t10 ^ t11;
			t13 = t10 | t11;
			d2 = t4 ^ t13;

			/* XOR keys and data */

			d0 = d0 ^ K[j++];
			d1 = d1 ^ K[j++];
			d2 = d2 ^ K[j++];
			d3 = d3 ^ K[j];

			j = i << 5;

			/* linear transformation */

			d2 = (d2 << 10) | (d2 >>> 22);
			d0 = (d0 << 27) | (d0 >>> 5);
			d2 = d2 ^ d3 ^ (d1 << 7);
			d0 = d0 ^ d1 ^ d3;
			d3 = (d3 << 25) | (d3 >>> 7);
			d1 = (d1 << 31) | (d1 >>> 1);
			d3 = d3 ^ d2 ^ (d0 << 3);
			d1 = d1 ^ d0 ^ d2;
			d2 = (d2 << 29) | (d2 >>> 3);
			d0 = (d0 << 19) | (d0 >>> 13);

			/* Gladmans boolean Si[0][i] function */

			t1 = ~d0;
			t2 = d0 ^ d1;
			t3 = t1 | t2;
			t4 = d3 ^ t3;
			t5 = d2 ^ t4;
			d2 = t2 ^ t5;
			t7 = d3 & t2;
			t8 = t1 ^ t7;
			t9 = d2 & t8;
			d1 = t4 ^ t9;
			t11 = d0 & t4;
			t12 = t5 | d1;
			d3 = t11 ^ t12;
			t14 = t5 ^ t8;
			d0 = d3 ^ t14;

			/* XOR keys and data */

			d0 = d0 ^ K[j++];
			d1 = d1 ^ K[j++];
			d2 = d2 ^ K[j++];
			d3 = d3 ^ K[j];
		}

		/* converting INT to output bytes */

		out[outoffset++] = (byte) d0;
		out[outoffset++] = (byte) (d0 >> 8);
		out[outoffset++] = (byte) (d0 >> 16);
		out[outoffset++] = (byte) (d0 >> 24);
		out[outoffset++] = (byte) d1;
		out[outoffset++] = (byte) (d1 >> 8);
		out[outoffset++] = (byte) (d1 >> 16);
		out[outoffset++] = (byte) (d1 >> 24);
		out[outoffset++] = (byte) d2;
		out[outoffset++] = (byte) (d2 >> 8);
		out[outoffset++] = (byte) (d2 >> 16);
		out[outoffset++] = (byte) (d2 >> 24);
		out[outoffset++] = (byte) d3;
		out[outoffset++] = (byte) (d3 >> 8);
		out[outoffset++] = (byte) (d3 >> 16);
		out[outoffset++] = (byte) (d3 >> 24);
	}

}
