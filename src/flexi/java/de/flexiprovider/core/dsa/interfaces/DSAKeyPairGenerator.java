package de.flexiprovider.core.dsa.interfaces;

import de.flexiprovider.api.keys.KeyPairGenerator;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.core.dsa.DSAParameterSpec;

/**
 * Translation layer between {@link java.security.interfaces.DSAParams} and
 * {@link DSAParameterSpec}.
 * 
 * @author Martin Döring
 */
public abstract class DSAKeyPairGenerator extends KeyPairGenerator {

    // ****************************************************
    // JCA adapter methods
    // ****************************************************

    /**
     * Translation method between {@link java.security.interfaces.DSAParams} and
     * {@link DSAParameterSpec}: initialize the key pair generator using the
     * specified parameter set and user-provided source of randomness. If
     * <tt>params</tt> is an instance of
     * {@link java.security.interfaces.DSAParams}, it is converted to an
     * instance of {@link DSAParameterSpec}.
     * 
     * @param params
     *                the parameter set used to generate the keys
     * @param javaRand
     *                the source of randomness for this generator
     * @throws java.security.InvalidAlgorithmParameterException
     *                 if the given parameters are inappropriate for this key
     *                 pair generator.
     */
    public void initialize(java.security.spec.AlgorithmParameterSpec params,
	    java.security.SecureRandom javaRand)
	    throws java.security.InvalidAlgorithmParameterException {

	if (params != null && !(params instanceof AlgorithmParameterSpec)
		&& (params instanceof java.security.interfaces.DSAParams)) {
	    AlgorithmParameterSpec dsaParams = new DSAParameterSpec(
		    (java.security.interfaces.DSAParams) params);
	    super.initialize(dsaParams, javaRand);
	} else {
	    super.initialize(params, javaRand);
	}
    }

}
