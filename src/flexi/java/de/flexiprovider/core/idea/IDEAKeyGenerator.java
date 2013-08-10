/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */
package de.flexiprovider.core.idea;

import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.api.keys.SecretKeyGenerator;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;

/**
 * This class is used to generate keys for the IDEA block cipher. The IDEA key
 * size is 128 bits.
 * 
 * @author Ralph Kuhnert
 * @author Anders Adamson
 */
public class IDEAKeyGenerator extends SecretKeyGenerator {

    /**
     * The IDEA key size (16 bytes)
     */
    public static final int IDEA_KEY_SIZE = 16;

    private SecureRandom random;

    // flag indicating whether the key generator has been initialized
    private boolean initialized;

    /**
     * Initialize the key generator. Since IDEA keys are of a fixed size and do
     * not require any parameters, this method only sets the source of
     * randomness.
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
     * Initialize the key generator. Since IDEA keys are of a fixed size, this
     * method only sets the source of randomness.
     * 
     * @param keySize
     *                the key size (not used)
     * @param random
     *                the source of randomness for this key generator
     */
    public void init(int keySize, SecureRandom random) {
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
     * Generate an IDEA key.
     * 
     * @return the generated {@link IDEAKey}
     */
    public SecretKey generateKey() {
	if (!initialized) {
	    init(Registry.getSecureRandom());
	}

	byte[] keyBytes = new byte[IDEA_KEY_SIZE];
	random.nextBytes(keyBytes);

	return new IDEAKey(keyBytes);
    }

}
