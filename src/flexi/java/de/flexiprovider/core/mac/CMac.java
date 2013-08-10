/*
 * Copyright (c) 1998-2007 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.mac;

import java.io.ByteArrayOutputStream;

import de.flexiprovider.api.BlockCipher;
import de.flexiprovider.api.Mac;
import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.exceptions.NoSuchModeException;
import de.flexiprovider.api.exceptions.NoSuchPaddingException;
import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.core.rijndael.Rijndael;

/**
 * This is an implementaion of the CMAC (<a
 * href="http://csrc.nist.gov/publications/nistpubs/800-38B/SP_800-38B.pdf">
 * NIST Special Publication 800-38B</a>).
 * 
 * @author Paul Nguentcheu
 */
public class CMac extends Mac {

	/*
	 * Inner classes providing concrete implementations of MAC with a variety of
	 * symmetric ciphers.
	 */

	/**
	 * A ByteArrayStream used to hold data
	 */
	private ByteArrayOutputStream cipher1Input;

	/**
	 * the key for this MAC computation.
	 */
	private SecretKey key;

	/**
	 * The algorithm parameters that are used in this MAC computation
	 */
	private AlgorithmParameterSpec algParSpecs;

	/**
	 * The references to the cipher objects.
	 */
	private BlockCipher cipher;

	/**
	 * The cipher that is used in the key expansion.
	 */
	private BlockCipher keyExpansionCipher;

	/**
	 * Source of randomness
	 */
	private SecureRandom sr;

	/**
	 * Blocksize of the cipher which is used
	 */
	private int blockSize;

	/**
	 * Length of the mac value in Bytes
	 */
	private int macLength;

	/**
	 * Constants used for the mac computation
	 */
	// DESede
	private static final int R64 = 0x1B;
	// AES
	private static final int R128 = 0x87;

	/**
	 * Subkeys
	 */
	private byte[] K1, K2;

	/*
	 * Inner classes providing concrete implementations of MAC with a variety of
	 * symmetric ciphers.
	 */

	/**
	 * CMAC with DESede algorithm
	 */
	public static class DESede extends CMac {
		/**
		 * The algorithm name.
		 */
		public static final String ALG_NAME = "CmacDESede";

		public DESede() {
			super(new de.flexiprovider.core.desede.DESede());
		}
	}

	/**
	 * CMAC with AES128 algorithm
	 */
	public static class AES128 extends CMac {
		/**
		 * The algorithm name.
		 */
		public static final String ALG_NAME = "CmacAES128";

		public AES128() {
			super(new Rijndael.AES.AES128_CBC());
		}
	}

	/**
	 * CMAC with AES192 algorithm
	 */
	public static class AES192 extends CMac {
		/**
		 * The algorithm name.
		 */
		public static final String ALG_NAME = "CmacAES192";

		public AES192() {
			super(new Rijndael.AES.AES192_CBC());
		}
	}

	/**
	 * CMAC with AES256 algorithm
	 */
	public static class AES256 extends CMac {
		/**
		 * The algorithm name.
		 */
		public static final String ALG_NAME = "CmacAES256";

		public AES256() {
			super(new Rijndael.AES.AES256_CBC());
		}
	}

	/**
	 * This constructor is called by every subclass for specifying the
	 * particular algorithm to be used for CMAC computation.
	 * 
	 * @param blockCipher
	 *            the cipher algorithm to use
	 */
	protected CMac(BlockCipher blockCipher) {
		cipher = blockCipher;
		try {
			keyExpansionCipher = (BlockCipher) blockCipher.getClass()
					.newInstance();
		} catch (InstantiationException e) {
			e.printStackTrace();
		} catch (IllegalAccessException e) {
			e.printStackTrace();
		}

		// set the mode
		try {
			cipher.setMode("CBC");
			keyExpansionCipher.setMode("CBC");
		} catch (NoSuchModeException e) {
			throw new RuntimeException(
					"Internal error: could not find mode 'CBC'.");
		}

		// set padding to none (since internal padding with one and zeroes is
		// applied)
		try {
			cipher.setPadding("NoPadding");
			keyExpansionCipher.setPadding("NoPadding");
		} catch (NoSuchPaddingException e) {
			throw new RuntimeException(
					"Internal error: could not find padding 'NoPadding'.");
		}
		macLength = cipher.getBlockSize();
		sr = Registry.getSecureRandom();
	}

	/**
	 * Returns the calculated MAC value. After the MAC finally has been
	 * calculated, the MAC object is reset for further MAC computations.
	 * 
	 * @return the calculated MAC value.
	 */
	public byte[] doFinal() {
		byte[] macValue = new byte[macLength];
		byte[] mess;
		int r;

		if (cipher == null) {
			throw new IllegalStateException("MAC not initialized");
		}

		r = cipher1Input.size() % blockSize;
		if ((r != 0) || (cipher1Input.size() == 0)) {
			// Padding
			cipher1Input.write((byte) 0x80);
			while (cipher1Input.size() % blockSize != 0) {
				cipher1Input.write((byte) 0x0);
			}
			mess = cipher1Input.toByteArray();
			int j = mess.length;
			for (int i = 0; i < blockSize; i++) {
				mess[j - blockSize + i] ^= K2[i];
			}
		} else {
			mess = cipher1Input.toByteArray();
			int j = mess.length;
			for (int i = 0; i < blockSize; i++) {
				mess[j - blockSize + i] ^= K1[i];
			}
		}

		try {
			byte[] result = cipher.doFinal(mess);
			System.arraycopy(result, result.length
					- (int) Math.ceil((double) macLength / blockSize)
					* blockSize, macValue, 0, macLength);
		} catch (Exception e) {
			System.err.println("dowhile encrypting failed");
			e.printStackTrace();
		}

		reset();
		return macValue;
	}

	/**
	 * Returns the length of the calculated MAC value in bytes.
	 * 
	 * @return the length of the MAC value
	 */
	public int getMacLength() {
		if (cipher == null) {
			throw new IllegalStateException("MAC not initialized");
		}
		return macLength;
	}

	/**
	 * Initializes this Mac Object with the given secret key and algorithm
	 * parameterSpec specification. The parameters are ignored.
	 * 
	 * @param key
	 *            the secret key with which this MAC object is initialized.
	 * @param params
	 *            the parameters
	 * @throws InvalidKeyException
	 *             if the key is invalid.
	 * @throws InvalidAlgorithmParameterException
	 *             if the parameters are inappropriate for initializing the
	 *             underlying block cipher.
	 */
	public void init(SecretKey key, AlgorithmParameterSpec params)
			throws InvalidKeyException, InvalidAlgorithmParameterException {
		this.key = key;
		this.algParSpecs = params;

		cipher.initEncrypt(key, params, sr);
		keyExpansionCipher.initEncrypt(key, params, sr);
		keySchedule(key.getEncoded());
		cipher1Input = new ByteArrayOutputStream();
		macLength = cipher.getBlockSize();
	}

	/**
	 * This method implements the CMac Key expansion. The subkeys K1 and K2 are
	 * stored in the variables <TT>K1, K2</TT>.
	 * 
	 * @param key
	 *            - the byte array containing the key.
	 */
	public void keySchedule(byte[] key) {
		blockSize = cipher.getBlockSize();
		int MSB = 0;
		int R = (blockSize == 8) ? R64 : R128;

		K2 = new byte[blockSize];
		K1 = new byte[blockSize];

		try {
			K1 = keyExpansionCipher.doFinal(K1);
			MSB = K1[0] & 0x80;
		} catch (Exception e) {
			System.err.println("dowhile encrypting failed");
			e.printStackTrace();
		}

		for (int i = 0; i < blockSize - 1; i++) {
			K1[i] = (byte) ((K1[i] << 1) | ((K1[i + 1] & 0xff) >>> 7));
		}
		K1[blockSize - 1] = (byte) (K1[blockSize - 1] << 1);

		if (MSB != 0) {
			K1[blockSize - 1] = (byte) (K1[blockSize - 1] ^ R);
		}
		System.arraycopy(K1, 0, K2, 0, blockSize);
		MSB = K2[0] & 0x80;
		for (int i = 0; i < blockSize - 1; i++) {
			K2[i] = (byte) ((K2[i] << 1) | ((K2[i + 1] & 0xff) >>> 7));
		}
		K2[blockSize - 1] = (byte) (K2[blockSize - 1] << 1);

		if (MSB != 0) {
			K2[blockSize - 1] = (byte) (K2[blockSize - 1] ^ R);
		}

	}

	/**
	 * Reset this MAC object so that it may be used for further MAC
	 * computations.
	 */
	public void reset() {
		cipher1Input = new ByteArrayOutputStream();
		try {
			init(key, algParSpecs);
		} catch (InvalidKeyException e) {
			// do nothing in reset
		} catch (InvalidAlgorithmParameterException e) {
			// do nothing in reset
		}
	}

	/**
	 * Processes the given byte
	 * 
	 * @param b
	 *            the byte to be processed.
	 */
	public void update(byte b) {
		if (cipher == null) {
			throw new IllegalStateException("MAC not initialized");
		}
		cipher1Input.write(b);
	}

	/**
	 * Processes the given number of bytes, supplied in a byte array starting at
	 * the given position.
	 * 
	 * @param bytes
	 *            byte array containing the message to be processed
	 * @param offset
	 *            offset into the array to start from
	 * @param len
	 *            number of bytes to be processed.
	 */
	public void update(byte[] bytes, int offset, int len) {
		if (cipher == null) {
			throw new IllegalStateException("MAC not initialized");
		}
		cipher1Input.write(bytes, offset, len);
	}

}
