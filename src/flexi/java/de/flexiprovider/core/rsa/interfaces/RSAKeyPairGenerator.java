package de.flexiprovider.core.rsa.interfaces;

import de.flexiprovider.api.keys.KeyPairGenerator;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.core.rsa.RSAKeyGenParameterSpec;

/**
 * Translation interface between
 * {@link java.security.spec.RSAKeyGenParameterSpec} and
 * {@link RSAKeyGenParameterSpec}.
 * 
 * @author Martin Döring
 */
public abstract class RSAKeyPairGenerator extends KeyPairGenerator {

    /**
     * Translation adapter for Java-AlgorithmParameterSpecs: initialize the key
     * pair generator using the specified parameters and source of randomness.
     * 
     * @param params
     *                the key generation parameters
     * @param javaRand
     *                the source of randomness
     * @throws java.security.InvalidAlgorithmParameterException
     *                 if the given parameters are inappropriate for this key
     *                 pair generator.
     */
    public void initialize(java.security.spec.AlgorithmParameterSpec params,
	    java.security.SecureRandom javaRand)
	    throws java.security.InvalidAlgorithmParameterException {

	if (params != null
		&& !(params instanceof AlgorithmParameterSpec)
		&& (params instanceof java.security.spec.RSAKeyGenParameterSpec)) {
	    java.security.spec.RSAKeyGenParameterSpec javaParams = (java.security.spec.RSAKeyGenParameterSpec) params;
	    RSAKeyGenParameterSpec rsaParams = new RSAKeyGenParameterSpec(
		    javaParams.getKeysize(), new FlexiBigInt(javaParams
			    .getPublicExponent()));
	    super.initialize(rsaParams, javaRand);
	} else {
	    super.initialize(params, javaRand);
	}
    }

}
