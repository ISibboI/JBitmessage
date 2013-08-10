/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.pbe;

import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.api.keys.SecretKeyGenerator;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;

/**
 * The key generator for PBEKeys.
 * 
 * @see de.flexiprovider.core.pbe.PBEKey
 * @author Thomas Wahrenbruch
 */
public class PBEKeyGenerator extends SecretKeyGenerator {

    // the key size in bytes
    private int keySize = 16;

    // the source of randomness
    private SecureRandom random = null;

    // flag indicating whether the key pair generator has been initialized
    private boolean initialized;

    /**
     * Initialize the key generator with the given parameters and source of
     * randomness. If the parameters are <tt>null</tt>, the
     * {@link PBEKeyGenParameterSpec#PBEKeyGenParameterSpec() default parameters}
     * are used.
     * 
     * @param params
     *                the parameters
     * @param random
     *                the source of randomness
     * @throws InvalidAlgorithmParameterException
     *                 if the parameters are not an instance of
     *                 {@link PBEKeyGenParameterSpec}.
     */
    public void init(AlgorithmParameterSpec params, SecureRandom random)
	    throws InvalidAlgorithmParameterException {

	PBEKeyGenParameterSpec pbeParams;
	if (params == null) {
	    pbeParams = new PBEKeyGenParameterSpec();
	} else if (params instanceof PBEKeyGenParameterSpec) {
	    pbeParams = (PBEKeyGenParameterSpec) params;
	} else {
	    throw new InvalidAlgorithmParameterException("unsupported type");
	}

	keySize = pbeParams.getKeySize();
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
	PBEKeyGenParameterSpec params = new PBEKeyGenParameterSpec(keySize);
	try {
	    init(params, random);
	} catch (InvalidAlgorithmParameterException e) {
	    // the parameters are correct and must be accepted
	    throw new RuntimeException("internal error");
	}
    }

    /**
     * Initialize the key generator with the default parameters and the given
     * source of randomness.
     * 
     * @param random
     *                the source of randomness
     */
    public void init(SecureRandom random) {
	PBEKeyGenParameterSpec defaultParams = new PBEKeyGenParameterSpec();
	try {
	    init(defaultParams, random);
	} catch (InvalidAlgorithmParameterException e) {
	    // the parameters are correct and must be accepted
	    throw new RuntimeException("internal error");
	}
    }

    /**
     * Generate a new PBEKey.
     * 
     * @return the generated {@link PBEKey}
     */
    public SecretKey generateKey() {
	if (!initialized) {
	    init(Registry.getSecureRandom());
	}

	byte[] out = new byte[keySize];
	char[] kchar = new char[keySize];
	random.nextBytes(out);

	for (int i = 0; i < keySize; i++) {
	    kchar[i] = (char) out[i];
	}

	return new PBEKey(kchar);
    }

}
