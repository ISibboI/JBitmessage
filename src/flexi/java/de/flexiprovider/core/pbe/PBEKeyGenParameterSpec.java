package de.flexiprovider.core.pbe;

import de.flexiprovider.api.parameters.AlgorithmParameterSpec;

/**
 * This class specifies parameters used for initializing the
 * {@link PBEKeyGenerator}. The parameters consist of the key size in bytes.
 * The default key size is 16 bytes.
 * 
 * @author Martin Döring
 */
public class PBEKeyGenParameterSpec implements AlgorithmParameterSpec {

    /**
     * The default key size (16 bytes)
     */
    public static final int DEFAULT_KEY_SIZE = 16;

    // the key size in bytes
    private int keySize;

    /**
     * Construct the default parameters. Choose key size as
     * {@link #DEFAULT_KEY_SIZE}.
     */
    public PBEKeyGenParameterSpec() {
	keySize = DEFAULT_KEY_SIZE;
    }

    /**
     * Construct new parameters from the given key size. If the key size is
     * invalid, the {@link #DEFAULT_KEY_SIZE default key size} is chosen.
     * 
     * @param keySize
     *                the key size (&gt;= 1 bytes)
     */
    public PBEKeyGenParameterSpec(int keySize) {
	if (keySize < 1) {
	    this.keySize = DEFAULT_KEY_SIZE;
	} else {
	    this.keySize = keySize;
	}
    }

    /**
     * @return the key size in bytes
     */
    public int getKeySize() {
	return keySize;
    }

}
