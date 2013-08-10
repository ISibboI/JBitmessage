package de.flexiprovider.core.dsa.interfaces;

import de.flexiprovider.api.Signature;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.core.dsa.DSAParameterSpec;

public abstract class DSASignature extends Signature {

    protected void engineSetParameter(
	    java.security.spec.AlgorithmParameterSpec params)
	    throws java.security.InvalidAlgorithmParameterException {

	if ((params != null) && !(params instanceof AlgorithmParameterSpec)
		&& (params instanceof java.security.interfaces.DSAParams)) {
	    AlgorithmParameterSpec dsaParams = new DSAParameterSpec(
		    (java.security.interfaces.DSAParams) params);
	    super.engineSetParameter(dsaParams);
	} else {
	    super.engineSetParameter(params);
	}
    }

}
