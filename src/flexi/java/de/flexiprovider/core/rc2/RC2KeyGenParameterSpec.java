package de.flexiprovider.core.rc2;

import de.flexiprovider.api.parameters.AlgorithmParameterSpec;

/**
 * This class specifies parameters used for initializing the
 * {@link RC2KeyGenerator}. The parameters consist of the key size in bits.
 * 
 * @author Martin Döring
 */
public class RC2KeyGenParameterSpec implements AlgorithmParameterSpec {

    /**
     * The default key size (128 bits)
     */
    public static final int DEFAULT_KEY_SIZE = 128;

    // the key size in bytes
    private int keySize;

    /**
     * Construct the default parameters. Choose key size as
     * {@link #DEFAULT_KEY_SIZE}.
     */
    public RC2KeyGenParameterSpec() {
	keySize = DEFAULT_KEY_SIZE;
    }

    /**
     * Construct new parameters from the given key size. If key size is &lt; 1,
     * the {@link #DEFAULT_KEY_SIZE default key size} is chosen.
     * 
     * @param keySize
     *                the key size in bits
     */
    public RC2KeyGenParameterSpec(int keySize) {
	if (keySize < 1) {
	    this.keySize = DEFAULT_KEY_SIZE;
	} else {
	    this.keySize = keySize;
	}
    }

    /**
     * @return the key size in bits
     */
    public int getKeySize() {
	return keySize;
    }

}
