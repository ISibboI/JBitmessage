/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.rc2;

import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;

/**
 * This class generates new keys for the RC2 block cipher. The default key size
 * is 64 bits.
 * 
 * @author Oliver Seiler
 */
public class RC2KeyGenerator extends
	de.flexiprovider.core.rc2.interfaces.RC2KeyGenerator {

    // the key size in bits
    private int keySize;

    // the source of randomness
    private SecureRandom random;

    // flag indicating whether the key generator has been initialized
    private boolean initialized;

    /**
     * Initialize the key generator with the given parameters and source of
     * randomness. If the parameters are <tt>null</tt>, the
     * {@link RC2KeyGenParameterSpec#RC2KeyGenParameterSpec() default parameters}
     * are used.
     * 
     * @param params
     *                the parameters
     * @param random
     *                the source of randomness
     * @throws InvalidAlgorithmParameterException
     *                 if the given parameters are <tt>null</tt> or not an
     *                 instance of {@link RC2KeyGenParameterSpec}.
     */
    public void init(AlgorithmParameterSpec params, SecureRandom random)
	    throws InvalidAlgorithmParameterException {

	RC2KeyGenParameterSpec rc2Params;
	if (params == null) {
	    rc2Params = new RC2KeyGenParameterSpec();
	} else if (params instanceof RC2KeyGenParameterSpec) {
	    rc2Params = (RC2KeyGenParameterSpec) params;
	} else {
	    throw new InvalidAlgorithmParameterException("unsupported type");
	}

	keySize = rc2Params.getKeySize();
	this.random = random != null ? random : Registry.getSecureRandom();

	initialized = true;
    }

    /**
     * Initialize this key generator with the given key size and source of
     * randomness.
     * 
     * @param keySize
     *                the key size in bits
     * @param random
     *                the source of randomness
     */
    public void init(int keySize, SecureRandom random) {
	RC2KeyGenParameterSpec params = new RC2KeyGenParameterSpec(keySize);
	try {
	    init(params, random);
	} catch (InvalidAlgorithmParameterException e) {
	    // the parameters are correct and must be accepted
	    throw new RuntimeException("internal error");
	}
    }

    /**
     * Initialize the key generator with the given source of randomness.
     * 
     * @param random
     *                the source of randomness
     */
    public void init(SecureRandom random) {
	RC2KeyGenParameterSpec defaultParams = new RC2KeyGenParameterSpec();
	try {
	    init(defaultParams, random);
	} catch (InvalidAlgorithmParameterException e) {
	    // the parameters are correct and must be accepted
	    throw new RuntimeException("internal error");
	}
    }

    /**
     * Generate an RC2 key.
     * 
     * @return the generated {@link RC2Key}
     */
    public SecretKey generateKey() {
	if (!initialized) {
	    init(Registry.getSecureRandom());
	}

	// generate random key bytes
	int byteSize = (keySize + 7) >> 3;
	byte[] keyBytes = new byte[byteSize];
	random.nextBytes(keyBytes);

	// mask unused bits
	keyBytes[byteSize - 1] &= (1 << (keySize & 7)) - 1;

	// return key
	return new RC2Key(keyBytes);
    }

}
