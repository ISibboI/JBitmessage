package de.flexiprovider.core.rsa;

import java.math.BigInteger;

import de.flexiprovider.api.keys.KeySpec;
import de.flexiprovider.common.math.FlexiBigInt;

public final class RSAPublicKeySpec extends java.security.spec.RSAPublicKeySpec
	implements KeySpec {

    // ****************************************************
    // JCA adapter methods
    // ****************************************************

    public RSAPublicKeySpec(BigInteger n, BigInteger e) {
	super(n, e);
    }

    /**
     * Create a new RSAPublicKeySpec out of the given
     * {@link java.security.spec.RSAPublicKeySpec}.
     * 
     * @param keySpec
     *                the {@link java.security.spec.RSAPublicKeySpec}
     */
    public RSAPublicKeySpec(java.security.spec.RSAPublicKeySpec keySpec) {
	super(keySpec.getModulus(), keySpec.getPublicExponent());
    }

    // ****************************************************
    // FlexiAPI methods
    // ****************************************************

    public RSAPublicKeySpec(FlexiBigInt n, FlexiBigInt e) {
	super(n.bigInt, e.bigInt);
    }

    /**
     * @return the modulus n
     */
    public FlexiBigInt getN() {
	return new FlexiBigInt(getModulus());
    }

    /**
     * @return the public exponent e
     */
    public FlexiBigInt getE() {
	return new FlexiBigInt(getPublicExponent());
    }

}
