/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */
package de.flexiprovider.core.rijndael;

import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.api.keys.SecretKeyGenerator;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;

/**
 * This class generates new keys for the Rijndael and AES block ciphers. Values
 * for the key size are 128, 192 or 256 bits, with the default being 128 bits.
 * 
 * @author Katja Rauch
 */
public class RijndaelKeyGenerator extends SecretKeyGenerator {

    // the key size in bits
    private int keySize;

    // the source of randomness
    private SecureRandom random;

    // flag indicating whether the key generator has been initialized
    private boolean initialized;

    /**
     * Initialize the key generator with the given parameters (which have to be
     * an instance of {@link RijndaelKeyGenParameterSpec}) and a source of
     * randomness. If the parameters are <tt>null</tt>, the
     * {@link RijndaelKeyGenParameterSpec#RijndaelKeyGenParameterSpec() default parameters}
     * are used.
     * 
     * @param params
     *                the parameters
     * @param random
     *                the source of randomness
     * @throws InvalidAlgorithmParameterException
     *                 if the parameters are <tt>null</tt> or not an instance
     *                 of {@link RijndaelKeyGenParameterSpec}.
     */
    public void init(AlgorithmParameterSpec params, SecureRandom random)
	    throws InvalidAlgorithmParameterException {

	RijndaelKeyGenParameterSpec rijndaelParams;
	if (params == null) {
	    rijndaelParams = new RijndaelKeyGenParameterSpec();
	} else if (params instanceof RijndaelKeyGenParameterSpec) {
	    rijndaelParams = (RijndaelKeyGenParameterSpec) params;
	} else {
	    throw new InvalidAlgorithmParameterException("unsupported type");
	}

	keySize = rijndaelParams.getKeySize() >> 3;
	this.random = random != null ? random : Registry.getSecureRandom();

	initialized = true;
    }

    /**
     * Initialize the key generator with the given key size and source of
     * randomness. If the key size is invalid, the
     * {@link RijndaelKeyGenParameterSpec#DEFAULT_KEY_SIZE default key size} is
     * chosen.
     * 
     * @param keySize
     *                the key size (128, 192, or 256 bits)
     * @param random
     *                the source of randomness
     */
    public void init(int keySize, SecureRandom random) {
	RijndaelKeyGenParameterSpec params = new RijndaelKeyGenParameterSpec(
		keySize);
	try {
	    init(params, random);
	} catch (InvalidAlgorithmParameterException e) {
	    // the parameters are correct and must be accepted
	    throw new RuntimeException("internal error");
	}
    }

    /**
     * Initialize the key generator with the default Rijndael parameters and the
     * given source of randomness.
     * 
     * @param random
     *                the source of randomness
     */
    public void init(SecureRandom random) {
	RijndaelKeyGenParameterSpec defaultParams = new RijndaelKeyGenParameterSpec();
	try {
	    init(defaultParams, random);
	} catch (InvalidAlgorithmParameterException e) {
	    // the parameters are correct and must be accepted
	    throw new RuntimeException("internal error");
	}
    }

    /**
     * Generate a Rijndael key.
     * 
     * @return the generated {@link RijndaelKey}
     */
    public SecretKey generateKey() {
	if (!initialized) {
	    init(Registry.getSecureRandom());
	}

	byte[] keyBytes = new byte[keySize];
	random.nextBytes(keyBytes);

	return new RijndaelKey(keyBytes);
    }

}
