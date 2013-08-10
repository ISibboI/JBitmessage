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
 * This is an implementation of the CBC MAC (ANSI X9.9) using the "flexicore"
 * jce implementation. Padding is only to put 0x00 until block boundary . We
 * emulate (single) DES by initializing all three parts of the key identically.
 * For reference look at V. Oorschot et. al. Handbook of Applied Cryptography
 * chapter 9.5.1 As here is no support for this algorithm directly it is
 * constructed using the following steps: 1. generating (single)des encryption
 * over cipher1Input value using following algorithm:
 * <code>Cipher.getInstance("DESede/CBC/NoPadding","FlexiCore");</code> 1.
 * creating an triple-DES key equivalent to DES by choosing keyA=keyB=keyC =
 * key1 2. decrypting result with algorithm
 * <code>Cipher.getInstance("DESede","FlexiCore");</code> using key
 * keyA=keyB=keyC = key2 3. encrypting result with algorithm
 * <code>Cipher.getInstance("DESede","FlexiCore");</code> using key
 * keyA=keyB=keyC = key1
 * 
 * @author Paul Nguentcheu
 */
public abstract class CBCMac extends Mac {

	// the underlying block cipher
	private BlockCipher cipher;

	// the source of randomness
	private SecureRandom sr;

	// the block size of the underlying cipher
	private int macLength;

	// a stream to hold the data
	private ByteArrayOutputStream cipherInput;

	/*
	 * Inner classes providing concrete implementations of CBCMac with a variety
	 * of symmetric ciphers.
	 */

	/**
	 * CBC-MAC with AES128 algorithm
	 */
	public static class AES128 extends CBCMac {
		/**
		 * The algorithm name.
		 */
		public static final String ALG_NAME = "CBCmacAES128";

		public AES128() {
			super(new Rijndael.AES.AES128_CBC());
		}
	}

	/**
	 * CBC-MAC with AES192 algorithm
	 */
	public static class AES192 extends CBCMac {
		/**
		 * The algorithm name.
		 */
		public static final String ALG_NAME = "CBCmacAES192";

		public AES192() {
			super(new Rijndael.AES.AES192_CBC());
		}
	}

	/**
	 * CBC-MAC with AES256 algorithm
	 */
	public static class AES256 extends CBCMac {
		/**
		 * The algorithm name.
		 */
		public static final String ALG_NAME = "CBCmacAES256";

		public AES256() {
			super(new Rijndael.AES.AES256_CBC());
		}
	}

	/**
	 * CBC-MAC with Camellia algorithm
	 */
	public static class Camellia extends CBCMac {
		/**
		 * The algorithm name.
		 */
		public static final String ALG_NAME = "CBCmacCamellia";

		public Camellia() {
			super(new de.flexiprovider.core.camellia.Camellia());
		}
	}

	/**
	 * CBC-MAC with DESede algorithm
	 */
	public static class DESede extends CBCMac {
		/**
		 * The algorithm name.
		 */
		public static final String ALG_NAME = "CBCmacDESede";

		public DESede() {
			super(new de.flexiprovider.core.desede.DESede.DESede_CBC());
		}
	}

	/**
	 * CBC-MAC with IDEA algorithm
	 */
	public static class IDEA extends CBCMac {
		/**
		 * The algorithm name.
		 */
		public static final String ALG_NAME = "CBCmacIDEA";

		public IDEA() {
			super(new de.flexiprovider.core.idea.IDEA.IDEA_CBC());
		}
	}

	/**
	 * CBC-MAC with MARS algorithm
	 */
	public static class MARS extends CBCMac {
		/**
		 * The algorithm name.
		 */
		public static final String ALG_NAME = "CBCmacMARS";

		public MARS() {
			super(new de.flexiprovider.core.mars.MARS());
		}
	}

	/**
	 * CBC-MAC with Misty1 algorithm
	 */
	public static class Misty1 extends CBCMac {
		/**
		 * The algorithm name.
		 */
		public static final String ALG_NAME = "CBCmacMisty1";

		public Misty1() {
			super(new de.flexiprovider.core.misty1.Misty1());
		}
	}

	/**
	 * CBC-MAC with RC2 algorithm
	 */
	public static class RC2 extends CBCMac {
		/**
		 * The algorithm name.
		 */
		public static final String ALG_NAME = "CBCmacRC2";

		public RC2() {
			super(new de.flexiprovider.core.rc2.RC2.RC2_CBC());
		}
	}

	/**
	 * CBC-MAC with RC5 algorithm
	 */
	public static class RC5 extends CBCMac {
		/**
		 * The algorithm name.
		 */
		public static final String ALG_NAME = "CBCmacRC5";

		public RC5() {
			super(new de.flexiprovider.core.rc5.RC5());
		}
	}

	/**
	 * CBC-MAC with RC6 algorithm
	 */
	public static class RC6 extends CBCMac {
		/**
		 * The algorithm name.
		 */
		public static final String ALG_NAME = "CBCmacRC6";

		public RC6() {
			super(new de.flexiprovider.core.rc6.RC6());
		}
	}

	/**
	 * CBC-MAC with SAFERPlus algorithm
	 */
	public static class SAFERPlus extends CBCMac {
		/**
		 * The algorithm name.
		 */
		public static final String ALG_NAME = "CBCmacSAFER+";

		public SAFERPlus() {
			super(new de.flexiprovider.core.saferplus.SAFERPlus());
		}
	}

	/**
	 * CBC-MAC with SAFERPlusPlus algorithm
	 */
	public static class SAFERPlusPlus extends CBCMac {
		/**
		 * The algorithm name.
		 */
		public static final String ALG_NAME = "CBCmacSAFER++";

		public SAFERPlusPlus() {
			super(new de.flexiprovider.core.saferplusplus.SAFERPlusPlus());
		}
	}

	/**
	 * CBC-MAC with Serpent algorithm
	 */
	public static class Serpent extends CBCMac {
		/**
		 * The algorithm name.
		 */
		public static final String ALG_NAME = "CBCmacSerpent";

		public Serpent() {
			super(new de.flexiprovider.core.serpent.Serpent());
		}
	}

	/**
	 * CBC-MAC with Shacal algorithm
	 */
	public static class Shacal extends CBCMac {
		/**
		 * The algorithm name.
		 */
		public static final String ALG_NAME = "CBCmacShacal";

		public Shacal() {
			super(new de.flexiprovider.core.shacal.Shacal());
		}
	}

	/**
	 * CBC-MAC with Shacal2 algorithm
	 */
	public static class Shacal2 extends CBCMac {
		/**
		 * The algorithm name.
		 */
		public static final String ALG_NAME = "CBCmacShacal2";

		public Shacal2() {
			super(new de.flexiprovider.core.shacal2.Shacal2());
		}
	}

	/**
	 * CBC-MAC with Twofish algorithm
	 */
	public static class Twofish extends CBCMac {
		/**
		 * The algorithm name.
		 */
		public static final String ALG_NAME = "CBCmacTwofish";

		public Twofish() {
			super(new de.flexiprovider.core.twofish.Twofish());
		}
	}

	/**
	 * This constructor is called by every subclass for specifying the
	 * particular algorithm to be used for CBC-MAC computation.
	 * 
	 * @param blockCipher
	 *            the cipher algorithm to use
	 */
	protected CBCMac(BlockCipher blockCipher) {
		cipher = blockCipher;

		// set the mode
		try {
			cipher.setMode("CBC");
		} catch (NoSuchModeException e) {
			throw new RuntimeException(
					"Internal error: could not find mode 'CBC'.");
		}

		// set padding to none (since internal padding with zeroes is applied)
		try {
			cipher.setPadding("NoPadding");
		} catch (NoSuchPaddingException e) {
			throw new RuntimeException(
					"Internal error: could not find padding 'NoPadding'.");
		}
		sr = Registry.getSecureRandom();
	}

	/**
	 * @return the length of the MAC value in bytes
	 */
	public int getMacLength() {
		return macLength;
	}

	/**
	 * Initialize this MAC with the given secret key and parameters.
	 * 
	 * @param key
	 *            the secret key
	 * @param params
	 *            the parameters
	 * @throws InvalidKeyException
	 *             if the key is invalid.
	 * @throws InvalidAlgorithmParameterException
	 *             if the parameters are invalid.
	 */
	public void init(SecretKey key, AlgorithmParameterSpec params)
			throws InvalidKeyException, InvalidAlgorithmParameterException {

		cipher.initEncrypt(key, params, sr);
		cipherInput = new ByteArrayOutputStream();
		macLength = cipher.getBlockSize();
	}

	/**
	 * Process the given byte
	 * 
	 * @param input
	 *            the byte to be processed
	 */
	public void update(byte input) {
		if (cipher == null) {
			throw new IllegalStateException("MAC not initialized");
		}
		cipherInput.write(input);
	}

	/**
	 * Process the given number of bytes, supplied in a byte array starting at
	 * the given position.
	 * 
	 * @param input
	 *            byte array containing the message to be processed
	 * @param inOff
	 *            offset into the array to start from
	 * @param inLen
	 *            number of bytes to be processed
	 */
	public void update(byte[] input, int inOff, int inLen) {
		if (cipher == null) {
			throw new IllegalStateException("MAC not initialized");
		}
		cipherInput.write(input, inOff, inLen);
	}

	/**
	 * Return the computed MAC value. After the MAC has been calculated, the MAC
	 * object is reset for further computations.
	 * 
	 * @return the computed MAC value
	 */
	public byte[] doFinal() {
		byte[] macValue = new byte[macLength];

		// Padding 000000
		int len = cipherInput.size();
		if ((len % macLength != 0) || (len == 0)) {
			int x = macLength - (len % macLength);
			for (int i = 0; i < x; i++) {
				cipherInput.write((byte) 0x0);
			}
		}

		try {
			byte[] result = cipher.doFinal(cipherInput.toByteArray());
			System.arraycopy(result, result.length - macLength, macValue, 0,
					macLength);
		} catch (Exception e) {
			System.err.println("doFinal failed");
			e.printStackTrace();
		}
		reset();
		return macValue;
	}

	/**
	 * Reset this MAC object so that it may be used for further MAC
	 * computations.
	 */
	public void reset() {
		cipherInput = new ByteArrayOutputStream();
	}

}
