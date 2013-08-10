/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */
package de.flexiprovider.core.desede;

import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.api.keys.SecretKeyGenerator;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;

/**
 * This class is used to generate keys for the DESede block cipher.
 * 
 * @author Norbert Trummel
 * @author Sylvain Franke
 */
public class DESedeKeyGenerator extends SecretKeyGenerator {

	private SecureRandom random;

	// flag indicating whether the key generator has been initialized
	private boolean initialized;

	/**
	 * Since DESede keys are of a fixed size and do not require any parameters,
	 * this method only sets the source of randomness.
	 * 
	 * @param params
	 *            the parameters (not used)
	 * @param random
	 *            the source of randomness
	 */
	public void init(AlgorithmParameterSpec params, SecureRandom random) {
		init(random);
	}

	/**
	 * Since DESede keys are of a fixed size, this method only sets the source
	 * of randomness.
	 * 
	 * @param strength
	 *            the key strength (not used)
	 * @param random
	 *            the source of randomness for this key generator
	 */
	public void init(int strength, SecureRandom random) {
		init(random);
	}

	/**
	 * Initialize the key generator with the given source of randomness.
	 * 
	 * @param random
	 *            the source of randomness
	 */
	public void init(SecureRandom random) {
		this.random = random != null ? random : Registry.getSecureRandom();
		initialized = true;
	}

	/**
	 * Generate a DESede key.
	 * 
	 * @return the generated {@link DESedeKey}
	 */
	public SecretKey generateKey() {
		if (!initialized) {
			init(Registry.getSecureRandom());
		}

		byte[] des_keyBytes = new byte[DESKeySpec.DES_KEY_LEN];
		byte[] des_ede_keyBytes = new byte[DESedeKeySpec.DES_EDE_KEY_LEN];
		int count = 0;
		do {
			random.nextBytes(des_keyBytes);
			setOddParity(des_keyBytes);

			try {
				if (DESKeySpec.isWeak(des_keyBytes, 0)) {
					continue;
				}
			} catch (InvalidKeyException e) {
				throw new RuntimeException(e.getMessage());
			}

			System.arraycopy(des_keyBytes, 0, des_ede_keyBytes, count
					* DESKeySpec.DES_KEY_LEN, DESKeySpec.DES_KEY_LEN);

			count++;
		} while (count < 3);

		return new DESedeKey(des_ede_keyBytes);
	}

	/**
	 * Set the lowest bit of every byte as a parity bit.
	 * 
	 * @param bytes
	 *            the byte array to set the parity on
	 */
	private static void setOddParity(byte[] bytes) {
		for (int i = 0; i < bytes.length; i++) {
			int b = bytes[i];

			b = ((b >> 1) ^ (b >> 2) ^ (b >> 3) ^ (b >> 4) ^ (b >> 5)
					^ (b >> 6) ^ (b >> 7)) & 0x01;

			if (b != 0) {
				bytes[i] = (byte) (bytes[i] & 0xfe);
			} else {
				// even # of 1's
				bytes[i] = (byte) (bytes[i] | 0x01);
			}
		}
	}

}
