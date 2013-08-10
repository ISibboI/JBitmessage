package de.flexiprovider.nf.iq.iqrdsa;

import de.flexiprovider.api.keys.KeySpec;
import de.flexiprovider.common.math.quadraticfields.QuadraticIdeal;

public class IQRDSAPublicKeySpec implements KeySpec {
    private IQRDSAParameterSpec params;

    private QuadraticIdeal gamma;

    private QuadraticIdeal alpha;

    public IQRDSAPublicKeySpec(IQRDSAParameterSpec params,
	    QuadraticIdeal gamma, QuadraticIdeal alpha) {
	this.params = params;
	this.gamma = gamma;
	this.alpha = alpha;
    }

    public IQRDSAParameterSpec getParams() {
	return params;
    }

    public QuadraticIdeal getGamma() {
	return gamma;
    }

    public QuadraticIdeal getAlpha() {
	return alpha;
    }

}
