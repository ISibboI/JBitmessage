package de.flexiprovider.nf.iq.iqrdsa;

import de.flexiprovider.api.keys.KeySpec;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.math.quadraticfields.QuadraticIdeal;

public class IQRDSAPrivateKeySpec implements KeySpec {

    private IQRDSAParameterSpec params;

    private FlexiBigInt a;

    private QuadraticIdeal gamma;

    private QuadraticIdeal alpha;

    public IQRDSAPrivateKeySpec(IQRDSAParameterSpec params,
	    QuadraticIdeal gamma, QuadraticIdeal alpha, FlexiBigInt a) {
	this.params = params;
	this.gamma = gamma;
	this.alpha = alpha;
	this.a = a;
    }

    public final IQRDSAParameterSpec getParams() {
	return params;
    }

    public final QuadraticIdeal getGamma() {
	return gamma;
    }

    public final QuadraticIdeal getAlpha() {
	return alpha;
    }

    public final FlexiBigInt getA() {
	return a;
    }

}
