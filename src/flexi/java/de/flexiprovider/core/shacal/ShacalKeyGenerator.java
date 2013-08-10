/*
 * Copyright (c) 1998-2007 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */
package de.flexiprovider.core.shacal;

import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.api.keys.SecretKeyGenerator;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;

/**
 * This class is used to generate keys for the Shacal block cipher. Values for
 * the key are 128, 192, 256, 320, 384, and 448 bits, with the default being 128
 * bits.
 * 
 * @author Paul Nguentcheu
 */
public class ShacalKeyGenerator extends SecretKeyGenerator {

    // the key size in bits
    private int keySize;

    // the source of randomness
    private SecureRandom random;

    // flag indicating whether the key generator has been initialized
    private boolean initialized;

    /**
     * Initialize the key generator with the given parameters (which have to be
     * an instance of {@link ShacalKeyGenParameterSpec}) and a source of
     * randomness. If the parameters are <tt>null</tt>, the
     * {@link ShacalKeyGenParameterSpec#ShacalKeyGenParameterSpec() default parameters}
     * are used.
     * 
     * @param params
     *                the parameters
     * @param random
     *                the source of randomness
     * @throws InvalidAlgorithmParameterException
     *                 if the parameters are not an instance of
     *                 {@link ShacalKeyGenParameterSpec}.
     */
    public void init(AlgorithmParameterSpec params, SecureRandom random)
	    throws InvalidAlgorithmParameterException {

	ShacalKeyGenParameterSpec shacalParams;
	if (params == null) {
	    shacalParams = new ShacalKeyGenParameterSpec();
	} else if (params instanceof ShacalKeyGenParameterSpec) {
	    shacalParams = (ShacalKeyGenParameterSpec) params;
	} else {
	    throw new InvalidAlgorithmParameterException("unsupported type");
	}

	keySize = shacalParams.getKeySize();
	this.random = random != null ? random : Registry.getSecureRandom();

	initialized = true;
    }

    /**
     * Initialize the key generator for a certain key size, using the given
     * source of randomness. If the key size is invalid, the default key length
     * is chosen (see {@link ShacalKeyGenParameterSpec}).
     * 
     * @param keySize
     *                the key size (128, 192, 256, 320, 384, or 448 bits)
     * @param random
     *                the source of randomness
     */
    public void init(int keySize, SecureRandom random) {
	ShacalKeyGenParameterSpec params = new ShacalKeyGenParameterSpec(
		keySize);
	try {
	    init(params, random);
	} catch (InvalidAlgorithmParameterException e) {
	    // the parameters are correct and must be accepted
	    throw new RuntimeException("internal error");
	}
    }

    /**
     * Initialize the key generator with the given source of randomness. The
     * default key size is chosen (see {@link ShacalKeyGenParameterSpec}).
     * 
     * @param random
     *                the source of randomness
     */
    public void init(SecureRandom random) {
	ShacalKeyGenParameterSpec defaultParams = new ShacalKeyGenParameterSpec();
	try {
	    init(defaultParams, random);
	} catch (InvalidAlgorithmParameterException e) {
	    // the parameters are correct and must be accepted
	    throw new RuntimeException("internal error");
	}
    }

    /**
     * Generate a Shacal key.
     * 
     * @return the generated {@link ShacalKey}
     */
    public SecretKey generateKey() {
	if (!initialized) {
	    init(Registry.getSecureRandom());
	}

	byte[] keyBytes = new byte[keySize >> 3];
	random.nextBytes(keyBytes);

	return new ShacalKey(keyBytes);
    }

}
