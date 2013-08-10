/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */
package de.flexiprovider.core.mars;

import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.api.keys.SecretKeyGenerator;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;

/**
 * This class is used to generate keys for the MARS block cipher. Values for the
 * key are 128, 192, 256, 320, 384, and 448 bits, with the default being 128
 * bits.
 * 
 * @author Katja Rauch
 */
public class MARSKeyGenerator extends SecretKeyGenerator {

    // the key size in bits
    private int keySize;

    // the source of randomness
    private SecureRandom random;

    // flag indicating whether the key pair generator has been initialized
    private boolean initialized;

    /**
     * Initialize the key generator with the given parameters (which have to be
     * an instance of {@link MARSKeyGenParameterSpec}) and a source of
     * randomness. If the parameters are <tt>null</tt>, the
     * {@link MARSKeyGenParameterSpec#MARSKeyGenParameterSpec() default parameters}
     * are used.
     * 
     * @param params
     *                the parameters
     * @param random
     *                the source of randomness
     * @throws InvalidAlgorithmParameterException
     *                 if the parameters are not an instance of
     *                 {@link MARSKeyGenParameterSpec}.
     */
    public void init(AlgorithmParameterSpec params, SecureRandom random)
	    throws InvalidAlgorithmParameterException {

	MARSKeyGenParameterSpec marsParams;
	if (params == null) {
	    marsParams = new MARSKeyGenParameterSpec();
	} else if (params instanceof MARSKeyGenParameterSpec) {
	    marsParams = (MARSKeyGenParameterSpec) params;
	} else {
	    throw new InvalidAlgorithmParameterException("unsupported type");
	}

	keySize = marsParams.getKeySize();
	this.random = random != null ? random : Registry.getSecureRandom();

	initialized = true;
    }

    /**
     * Initialize the key generator with the given key size and source of
     * randomness.
     * 
     * @param keySize
     *                the key size
     * @param random
     *                the source of randomness
     */
    public void init(int keySize, SecureRandom random) {
	MARSKeyGenParameterSpec params = new MARSKeyGenParameterSpec(keySize);
	try {
	    init(params, random);
	} catch (InvalidAlgorithmParameterException e) {
	    // the parameters are correct and must be accepted
	    throw new RuntimeException("internal error");
	}
    }

    /**
     * Initialize the key generator with the given source of randomness. The
     * default key size is chosen (see {@link MARSKeyGenParameterSpec}).
     * 
     * @param random
     *                the source of randomness
     */
    public void init(SecureRandom random) {
	MARSKeyGenParameterSpec defaultParams = new MARSKeyGenParameterSpec();
	try {
	    init(defaultParams, random);
	} catch (InvalidAlgorithmParameterException e) {
	    // the parameters are correct and must be accepted
	    throw new RuntimeException("internal error");
	}
    }

    /**
     * Generate a MARS key.
     * 
     * @return the generated {@link MARSKey}
     */
    public SecretKey generateKey() {
	if (!initialized) {
	    init(Registry.getSecureRandom());
	}

	byte[] keyBytes = new byte[keySize >> 3];
	random.nextBytes(keyBytes);

	return new MARSKey(keyBytes);
    }

}
