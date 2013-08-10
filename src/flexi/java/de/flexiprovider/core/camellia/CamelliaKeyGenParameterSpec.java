package de.flexiprovider.core.camellia;

import de.flexiprovider.api.parameters.AlgorithmParameterSpec;

/**
 * This class specifies parameters used for initializing the
 * {@link CamelliaKeyGenerator}. The parameters consist of the key size in
 * bits. Values for the key size are 128, 192, and 256 bits, with the default
 * being 128 bits.
 * 
 * @author Martin Döring
 */
public class CamelliaKeyGenParameterSpec implements AlgorithmParameterSpec {

    /**
     * The default key size (128 bits)
     */
    public static final int DEFAULT_KEY_SIZE = 128;

    // the key size in bits
    private int keySize;

    /**
     * Construct the default parameters. Choose key size as
     * {@link #DEFAULT_KEY_SIZE}.
     */
    public CamelliaKeyGenParameterSpec() {
	keySize = DEFAULT_KEY_SIZE;
    }

    /**
     * Construct new parameters from the given key size. If the key size is
     * invalid, the {@link #DEFAULT_KEY_SIZE default key size} is chosen.
     * 
     * @param keySize
     *                the key size (128, 192, or 256 bits)
     */
    public CamelliaKeyGenParameterSpec(int keySize) {
	if ((keySize != 128) && (keySize != 192) && (keySize != 256)) {
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
