package de.flexiprovider.nf.iq.iqdsa;

import de.flexiprovider.api.keys.KeySpec;
import de.flexiprovider.common.math.FlexiBigInt;

/**
 * This class provides the specification for IQDSA private keys.
 */
public class IQDSAPrivateKeySpec implements KeySpec {

    private IQDSAParameterSpec params;

    private FlexiBigInt a;

    /**
     * Construct an IQDSA private key specification from the given parameters
     * and integer.
     * 
     * @param params
     *                the parameters
     * @param a
     *                the integer
     */
    public IQDSAPrivateKeySpec(IQDSAParameterSpec params, FlexiBigInt a) {
	this.params = params;
	this.a = a;
    }

    /**
     * @return the parameters
     */
    public IQDSAParameterSpec getParams() {
	return params;
    }

    /**
     * @return the integer <tt>a</tt>
     */
    public FlexiBigInt getA() {
	return a;
    }

}
