/*
 * Copyright (c) 1998-2008 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */
package de.flexiprovider.core.mac;

import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.api.keys.SecretKeyGenerator;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;

/**
 * This class is used to generate keys for the Message Authentication Code
 * TwoTrackMac. The TwoTrackMac key size is 20 bytes (160 bits).
 * 
 * @author Paul Nguentcheu
 */
public class TwoTrackMacKeyGenerator extends SecretKeyGenerator {

    /**
     * The TwoTrackMac key size (20 bytes)
     */
    public static final int TTMAC_KEY_SIZE = 20;

    // the source of randomness
    private SecureRandom random;

    // flag indicating whether the key generator has been initialized
    private boolean initialized;

    /**
     * Initialize the key generator. Since TwoTrackMac keys are of a fixed size
     * and do not require any parameters, this method only sets the source of
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
     * Initialize the key generator. Since TwoTrackMac keys are of a fixed size,
     * this method only sets the source of randomness.
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
     * Initialize the key generator with a source of randomness.
     * 
     * @param random
     *                the source of randomness
     */
    public void init(SecureRandom random) {
	this.random = random != null ? random : Registry.getSecureRandom();
	initialized = true;
    }

    /**
     * Generate a TwoTrackMac key.
     * 
     * @return the generated {@link TwoTrackMacKey}
     */
    public SecretKey generateKey() {
	if (!initialized) {
	    init(Registry.getSecureRandom());
	}

	byte[] keyBytes = new byte[TTMAC_KEY_SIZE];
	random.nextBytes(keyBytes);

	return new TwoTrackMacKey(keyBytes);
    }

}
