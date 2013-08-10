package de.flexiprovider.core.pbe.interfaces;

import de.flexiprovider.api.Cipher;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.core.pbe.PBEParameterSpec;

/**
 * Translation layer between {@link javax.crypto.spec.PBEParameterSpec} and
 * {@link PBEParameterSpec}.
 * 
 * @author Martin Döring
 */
public abstract class PBES1 extends Cipher {

    /**
     * Translation method between {@link javax.crypto.spec.PBEParameterSpec} and
     * {@link PBEParameterSpec}: initialize this cipher with a key, a set of
     * algorithm parameters, and a source of randomness. The cipher is
     * initialized for one of the following four operations: encryption,
     * decryption, key wrapping or key unwrapping, depending on the value of
     * opMode. If this cipher (including its underlying feedback or padding
     * scheme) requires any random bytes (e.g., for parameter generation), it
     * will get them from random. Note that when a Cipher object is initialized,
     * it loses all previously-acquired state. In other words, initializing a
     * Cipher is equivalent to creating a new instance of that Cipher and
     * initializing it.
     * 
     * @param opMode
     *                the operation mode of this cipher (this is one of the
     *                following: ENCRYPT_MODE, DECRYPT_MODE)
     * @param key
     *                the encryption key
     * @param params
     *                the algorithm parameters
     * @param javaRand
     *                the source of randomness
     * @throws java.security.InvalidKeyException
     *                 if the given key is inappropriate for initializing this
     *                 cipher
     * @throws java.security.InvalidAlgorithmParameterException
     *                 if the given algorithm parameters are inappropriate for
     *                 this cipher, or if this cipher is being initialized for
     *                 decryption and requires algorithm parameters and the
     *                 parameters are null.
     */
    protected final void engineInit(int opMode, java.security.Key key,
	    java.security.spec.AlgorithmParameterSpec params,
	    java.security.SecureRandom javaRand)
	    throws java.security.InvalidKeyException,
	    java.security.InvalidAlgorithmParameterException {

	if ((params != null) && !(params instanceof AlgorithmParameterSpec)
		&& (params instanceof javax.crypto.spec.PBEParameterSpec)) {
	    AlgorithmParameterSpec pbeParams = new PBEParameterSpec(
		    (javax.crypto.spec.PBEParameterSpec) params);
	    super.engineInit(opMode, key, pbeParams, javaRand);
	} else {
	    super.engineInit(opMode, key, params, javaRand);
	}
    }
}
