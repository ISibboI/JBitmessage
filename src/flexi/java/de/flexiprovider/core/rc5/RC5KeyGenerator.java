/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */
package de.flexiprovider.core.rc5;

import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.api.keys.SecretKeyGenerator;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;

/**
 * This class generates new keys for the RC5 block cipher. The default key size
 * is 128 bits.
 * 
 * @author Oliver Seiler
 */
public class RC5KeyGenerator extends SecretKeyGenerator {

    // the key size in bytes
    private int keySize;

    // the source of randomness
    private SecureRandom random;

    // flag indicating whether the key generator has been initialized
    private boolean initialized;

    /**
     * Initialize the key generator with the given parameters and source of
     * randomness. If the parameters are <tt>null</tt>, the
     * {@link RC5KeyGenParameterSpec#RC5KeyGenParameterSpec() default parameters}
     * are used.
     * 
     * @param params
     *                the parameters
     * @param random
     *                the source of randomness
     * @throws InvalidAlgorithmParameterException
     *                 if the parameters are <tt>null</tt> not an instance of
     *                 {@link RC5KeyGenParameterSpec}.
     */
    public void init(AlgorithmParameterSpec params, SecureRandom random)
	    throws InvalidAlgorithmParameterException {

	RC5KeyGenParameterSpec rc5Params;
	if (params == null) {
	    rc5Params = new RC5KeyGenParameterSpec();
	} else if (params instanceof RC5KeyGenParameterSpec) {
	    rc5Params = (RC5KeyGenParameterSpec) params;
	} else {
	    throw new InvalidAlgorithmParameterException("unsupported type");
	}

	keySize = (rc5Params.getKeySize() + 7) >> 3;
	this.random = random != null ? random : Registry.getSecureRandom();

	initialized = true;
    }

    /**
     * Initialize the key generator with the given key size and source of
     * randomness.
     * 
     * @param keySize
     *                the key size in bytes
     * @param random
     *                the source of randomness
     */
    public void init(int keySize, SecureRandom random) {
	RC5KeyGenParameterSpec params = new RC5KeyGenParameterSpec(keySize);
	try {
	    init(params, random);
	} catch (InvalidAlgorithmParameterException e) {
	    // the parameters are correct and must be accepted
	    throw new RuntimeException("internal error");
	}
    }

    /**
     * Initialize the key generator with the default key size and the given
     * source of randomness.
     * 
     * @param random
     *                the source of randomness
     */
    public void init(SecureRandom random) {
	RC5KeyGenParameterSpec defaultParams = new RC5KeyGenParameterSpec();
	try {
	    init(defaultParams, random);
	} catch (InvalidAlgorithmParameterException e) {
	    // the parameters are correct and must be accepted
	    throw new RuntimeException("internal error");
	}
    }

    /**
     * Generate an RC5 key.
     * 
     * @return the generated {@link RC5Key}
     */
    public SecretKey generateKey() {
	if (!initialized) {
	    init(Registry.getSecureRandom());
	}

	byte[] keyBytes = new byte[keySize];
	random.nextBytes(keyBytes);

	return new RC5Key(keyBytes);
    }

}
