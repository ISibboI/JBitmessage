package de.flexiprovider.nf.iq.iqgq;

import de.flexiprovider.api.keys.KeySpec;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.math.quadraticfields.QuadraticIdeal;

public class IQGQPublicKeySpec implements KeySpec {
    private IQGQParameterSpec params;

    private QuadraticIdeal alpha;

    private FlexiBigInt exponent;

    public IQGQPublicKeySpec(IQGQParameterSpec params, QuadraticIdeal alpha,
	    FlexiBigInt exponent) {
	this.params = params;
	this.alpha = alpha;
	this.exponent = exponent;
    }

    public IQGQParameterSpec getParams() {
	return params;
    }

    public QuadraticIdeal getAlpha() {
	return alpha;
    }

    public FlexiBigInt getExponent() {
	return exponent;
    }

}
