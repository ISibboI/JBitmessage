/*
 * Copyright (c) 1998-2007 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */
package de.flexiprovider.core.shacal2;

import de.flexiprovider.api.parameters.AlgorithmParameterSpec;

/**
 * This class specifies parameters used for initializing the
 * {@link Shacal2KeyGenerator}. The parameters consist of the key size in bits.
 * Values for the key are 128, 192, 256, 320, 384, and 448 bits, with the
 * default being 128 bits.
 * 
 * @author Paul Nguentcheu
 * @author Martin Döring
 */
public class Shacal2KeyGenParameterSpec implements AlgorithmParameterSpec {

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
    public Shacal2KeyGenParameterSpec() {
	keySize = DEFAULT_KEY_SIZE;
    }

    /**
     * Construct new parameters from the given key size. If the key size is
     * invalid, the {@link #DEFAULT_KEY_SIZE default key size} is chosen.
     * 
     * @param keySize
     *                the key size (128, 192, 256, 320, 384, or 448 bits)
     */
    public Shacal2KeyGenParameterSpec(int keySize) {
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
