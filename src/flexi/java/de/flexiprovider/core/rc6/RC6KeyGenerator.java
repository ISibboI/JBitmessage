/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.rc6;

import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.api.keys.SecretKeyGenerator;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;

/**
 * This class generates new keys for the RC6 block cipher. Values for the key
 * size are 128, 192, and 256 bits, with the default being 128 bits.
 * 
 * @author Christoph Sesterhenn
 * @author Christoph Ender
 */
public class RC6KeyGenerator extends SecretKeyGenerator {

    private int keySize;

    private SecureRandom random;

    // flag indicating whether the key generator has been initialized
    private boolean initialized;

    /**
     * Initialize the key generator with the given parameters (which have to be
     * an instance of {@link RC6KeyGenParameterSpec}) and a source of
     * randomness. If the parameters are <tt>null</tt>, the
     * {@link RC6KeyGenParameterSpec#RC6KeyGenParameterSpec() default parameters}
     * are used.
     * 
     * @param params
     *                the parameters
     * @param random
     *                the source of randomness
     * @throws InvalidAlgorithmParameterException
     *                 if the parameters are <tt>null</tt> or not an instance
     *                 of {@link RC6KeyGenParameterSpec}.
     */
    public void init(AlgorithmParameterSpec params, SecureRandom random)
	    throws InvalidAlgorithmParameterException {

	RC6KeyGenParameterSpec rc6Params;
	if (params == null) {
	    rc6Params = new RC6KeyGenParameterSpec();
	} else if (params instanceof RC6KeyGenParameterSpec) {
	    rc6Params = (RC6KeyGenParameterSpec) params;
	} else {
	    throw new InvalidAlgorithmParameterException("unsupported type");
	}

	keySize = rc6Params.getKeySize() >> 3;
	this.random = random != null ? random : Registry.getSecureRandom();

	initialized = true;
    }

    /**
     * Initialize the key generator with the given key size and source of
     * randomness. If the key size is invalid, the
     * {@link RC6KeyGenParameterSpec#DEFAULT_KEY_SIZE default key size} is
     * chosen.
     * 
     * @param keySize
     *                the key size (128, 192, or 256 bits)
     * @param random
     *                the source of randomness
     */
    public void init(int keySize, SecureRandom random) {
	RC6KeyGenParameterSpec params = new RC6KeyGenParameterSpec(keySize);
	try {
	    init(params, random);
	} catch (InvalidAlgorithmParameterException e) {
	    // the parameters are correct and must be accepted
	    throw new RuntimeException("internal error");
	}
    }

    /**
     * Initialize the key generator with the default RC6 parameters and the
     * given source of randomness.
     * 
     * @param random
     *                the source of randomness
     */
    public void init(SecureRandom random) {
	RC6KeyGenParameterSpec defaultParams = new RC6KeyGenParameterSpec();
	try {
	    init(defaultParams, random);
	} catch (InvalidAlgorithmParameterException e) {
	    // the parameters are correct and must be accepted
	    throw new RuntimeException("internal error");
	}
    }

    /**
     * Generate an RC6 key.
     * 
     * @return the generated {@link RC6Key}
     */
    public SecretKey generateKey() {
	if (!initialized) {
	    init(Registry.getSecureRandom());
	}

	byte[] keyBytes = new byte[keySize];
	random.nextBytes(keyBytes);

	return new RC6Key(keyBytes);
    }

}
