package de.flexiprovider.nf.iq.iqgq;

import de.flexiprovider.api.keys.KeySpec;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.math.quadraticfields.QuadraticIdeal;

public class IQGQPrivateKeySpec implements KeySpec {
    private IQGQParameterSpec params;

    private QuadraticIdeal theta;

    private FlexiBigInt exponent;

    public IQGQPrivateKeySpec(IQGQParameterSpec params, QuadraticIdeal theta,
	    FlexiBigInt exponent) {
	this.params = params;
	this.theta = theta;
	this.exponent = exponent;
    }

    public IQGQParameterSpec getParams() {
	return params;
    }

    public QuadraticIdeal getTheta() {
	return theta;
    }

    public FlexiBigInt getExponent() {
	return exponent;
    }

}
