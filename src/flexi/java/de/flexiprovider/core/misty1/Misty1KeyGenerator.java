/*
 * Copyright (c) 1998-2007 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.misty1;

import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.api.keys.SecretKeyGenerator;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;

/**
 * This class generates new keys for the Misty1 block cipher. The Misty1 key
 * size is 128 bits.
 * 
 * @author Paul Nguentcheu
 */
public class Misty1KeyGenerator extends SecretKeyGenerator {

    /**
     * The Misty1 key size (16 bytes)
     */
    public static final int MISTY1_KEY_SIZE = 16;

    private SecureRandom random;

    // flag indicating whether the key generator has been initialized
    private boolean initialized;

    /**
     * Since Misty1 keys are of a fixed size and do not require any parameters,
     * this method only sets the source of randomness.
     * 
     * @param params
     *                the parameters (not used)
     * @param random
     *                the source of randomness
     */
    public void init(AlgorithmParameterSpec params, SecureRandom random) {
	init(random);
    }

    /**
     * Since Misty1 keys are of a fixed size, this method only sets the source
     * of randomness.
     * 
     * @param strength
     *                the key strength (not used)
     * @param random
     *                the source of randomness for this key generator
     */
    public void init(int strength, SecureRandom random) {
	init(random);
    }

    /**
     * Initialize the key generator with the given source of randomness.
     * 
     * @param random
     *                the source of randomness
     */
    public void init(SecureRandom random) {
	this.random = random != null ? random : Registry.getSecureRandom();
	initialized = true;
    }

    /**
     * Generate a Misty1 key.
     * 
     * @return the generated {@link Misty1Key}
     */
    public SecretKey generateKey() {
	if (!initialized) {
	    init(Registry.getSecureRandom());
	}

	byte[] bytes = new byte[MISTY1_KEY_SIZE];
	random.nextBytes(bytes);

	return new Misty1Key(bytes);
    }

}
