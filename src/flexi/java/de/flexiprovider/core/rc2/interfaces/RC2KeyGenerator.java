package de.flexiprovider.core.rc2.interfaces;

import de.flexiprovider.api.keys.SecretKeyGenerator;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.core.rc2.RC2KeyGenParameterSpec;

public abstract class RC2KeyGenerator extends SecretKeyGenerator {

    protected void engineInit(java.security.spec.AlgorithmParameterSpec params,
	    java.security.SecureRandom javaRand)
	    throws java.security.InvalidAlgorithmParameterException {
	if (params != null && !(params instanceof AlgorithmParameterSpec)
		&& (params instanceof javax.crypto.spec.RC2ParameterSpec)) {
	    javax.crypto.spec.RC2ParameterSpec javaParams = (javax.crypto.spec.RC2ParameterSpec) params;
	    RC2KeyGenParameterSpec rc2Params = new RC2KeyGenParameterSpec(
		    javaParams.getEffectiveKeyBits());
	    super.engineInit(rc2Params, javaRand);
	} else {
	    super.engineInit(params, javaRand);
	}
    }

}
