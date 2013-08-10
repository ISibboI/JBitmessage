package de.flexiprovider.core.elgamal;

import de.flexiprovider.api.exceptions.InvalidParameterException;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;

/**
 * This class specifies parameters used for initializing the
 * {@link ElGamalKeyPairGenerator}. The parameters consist of the bit length of
 * the prime <tt>p</tt>. The default bit length is 1024 bits.
 * 
 * @author Martin Döring
 */
public class ElGamalKeyGenParameterSpec implements AlgorithmParameterSpec {

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
    public ElGamalKeyGenParameterSpec() {
	keySize = DEFAULT_KEY_SIZE;
    }

    /**
     * Construct new parameters from the given bit length of the prime
     * <tt>p</tt>. If the length is invalid, the
     * {@link #DEFAULT_KEY_SIZE default length} is chosen.
     * 
     * @param keySize
     *                the bit length of the prime <tt>p</tt> (>= 512 bits)
     * @throws InvalidParameterException
     *                 if the key size is less than 512 bits.
     */
    public ElGamalKeyGenParameterSpec(int keySize)
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
