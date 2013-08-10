/*
 * Copyright (c) 1998-2007 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */
package de.flexiprovider.core.mars;

import de.flexiprovider.api.parameters.AlgorithmParameterSpec;

/**
 * This class specifies parameters used for initializing the
 * {@link MARSKeyGenerator}. The parameters consist of the key size in bits.
 * Values for the key are 128, 192, 256, 320, 384, and 448 bits, with the
 * default being 128 bits.
 * 
 * @author Katja Rauch
 * @author Martin Döring
 */
public class MARSKeyGenParameterSpec implements AlgorithmParameterSpec {

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
    public MARSKeyGenParameterSpec() {
	keySize = DEFAULT_KEY_SIZE;
    }

    /**
     * Construct new parameters from the given key size. If the key size is
     * invalid, the {@link #DEFAULT_KEY_SIZE default key size} is chosen.
     * 
     * @param keySize
     *                the key size (128, 192, 256, 320, 384, or 448 bits)
     */
    public MARSKeyGenParameterSpec(int keySize) {
	if ((keySize != 128) && (keySize != 192) && (keySize != 256)
		&& (keySize != 320) && (keySize != 384) && (keySize != 448)) {
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
