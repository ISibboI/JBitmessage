package de.flexiprovider.core.pbe.interfaces;

import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.api.parameters.AlgorithmParameters;
import de.flexiprovider.core.pbe.PBEParameterSpec;

/**
 * Translation layer between {@link javax.crypto.spec.PBEParameterSpec} and
 * {@link PBEParameterSpec}.
 * 
 * @author Martin Döring
 */
public abstract class PBEParameters extends AlgorithmParameters {

    /**
     * Translation method between {@link javax.crypto.spec.PBEParameterSpec} and
     * {@link PBEParameterSpec}: initialize this parameters object using the
     * parameters specified in <tt>paramSpec</tt>.
     * 
     * @param params
     *                the parameter specification
     * @throws java.security.spec.InvalidParameterSpecException
     *                 if <tt>paramSpec</tt> is inappropriate for
     *                 initialization.
     */
    protected final void engineInit(
	    java.security.spec.AlgorithmParameterSpec params)
	    throws java.security.spec.InvalidParameterSpecException {

	if ((params != null) && !(params instanceof AlgorithmParameterSpec)
		&& (params instanceof javax.crypto.spec.PBEParameterSpec)) {
	    AlgorithmParameterSpec pbeParams = new PBEParameterSpec(
		    (javax.crypto.spec.PBEParameterSpec) params);
	    super.engineInit(pbeParams);
	} else {
	    super.engineInit(params);
	}
    }

    /**
     * Translation method between {@link javax.crypto.spec.PBEParameterSpec} and
     * {@link PBEParameterSpec}: return a (transparent) specification of this
     * parameters object. <tt>paramSpec</tt> identifies the specification
     * class in which the parameters should be returned. It could, for example,
     * be {@link java.security.spec.DSAParameterSpec}<tt>.class</tt> , to
     * indicate that the parameters should be returned in an instance of the
     * {@link java.security.spec.DSAParameterSpec} class.
     * 
     * @param paramSpec
     *                the the specification class in which the parameters should
     *                be returned
     * @return the parameter specification
     * @throws java.security.spec.InvalidParameterSpecException
     *                 if the requested parameter specification is inappropriate
     *                 for this parameter object.
     */
    protected final java.security.spec.AlgorithmParameterSpec engineGetParameterSpec(
	    Class paramSpec)
	    throws java.security.spec.InvalidParameterSpecException {

	if (paramSpec.equals(javax.crypto.spec.PBEParameterSpec.class)) {
	    return super.engineGetParameterSpec(PBEParameterSpec.class);
	}

	return super.engineGetParameterSpec(paramSpec);
    }

}
