/* Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.elgamal.semanticallysecure;

import de.flexiprovider.api.exceptions.InvalidParameterException;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;

/**
 * This class specifies parameters used for initializing the
 * {@link SSVElGamalKeyPairGenerator}. The parameters consist of the bit length
 * of the prime <tt>p</tt>. The default bit length is 1024 bits.
 * 
 * @author Martin Döring
 * @author Roberto Samarone dos Santos Araújo
 * 
 */
public class SSVElGamalKeyGenParameterSpec implements AlgorithmParameterSpec {

	/**
	 * The default bit length of the prime <tt>p</tt> (1024 bits)
	 */
	public static final int DEFAULT_KEY_SIZE = 1024;

	// the bit length of the prime p
	private int keySize;

	/**
	 * Construct the default parameters. Choose the bit length of the prime
	 * <tt>p</tt> as {@link #DEFAULT_KEY_SIZE}.
	 */
	public SSVElGamalKeyGenParameterSpec() {
		keySize = DEFAULT_KEY_SIZE;
	}

	/**
	 * Construct new parameters from the given bit length of the prime
	 * <tt>p</tt>. If the length is invalid, the {@link #DEFAULT_KEY_SIZE
	 * default length} is chosen.
	 * 
	 * @param keySize
	 *            the bit length of the prime <tt>p</tt> (>= 512 bits)
	 * @throws InvalidParameterException
	 *             if the key size is less than 512 bits.
	 */
	public SSVElGamalKeyGenParameterSpec(int keySize)
			throws InvalidParameterException {
		if (keySize < 512) {
			throw new InvalidParameterException("key size must be >= 512");
		}
		this.keySize = keySize;
	}

	/**
	 * @return the bit length of the prime <tt>p</tt>
	 */
	public int getKeySize() {
		return keySize;
	}

}
