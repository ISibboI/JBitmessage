package de.flexiprovider.nf.iq.iqdsa;

import de.flexiprovider.api.keys.KeySpec;
import de.flexiprovider.common.math.quadraticfields.QuadraticIdeal;

/**
 * This class provides the specification for IQDSA public keys.
 */
public class IQDSAPublicKeySpec implements KeySpec {

    private IQDSAParameterSpec params;

    private QuadraticIdeal alpha;

    /**
     * Construct an IQDSA public key specification from the given parameters and
     * the base element of the NFDL-problem.
     * 
     * @param params
     *                the parameters
     * @param alpha
     *                the base element of the NFDL-problem
     */
    public IQDSAPublicKeySpec(IQDSAParameterSpec params, QuadraticIdeal alpha) {
	this.params = params;
	this.alpha = alpha;
    }

    /**
     * @return the parameters
     */
    public IQDSAParameterSpec getParams() {
	return params;
    }

    /**
     * @return the base element of the NFDL-problem
     */
    public QuadraticIdeal getAlpha() {
	return alpha;
    }

}
