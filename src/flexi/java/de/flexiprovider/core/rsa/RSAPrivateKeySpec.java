package de.flexiprovider.core.rsa;

import java.math.BigInteger;

import de.flexiprovider.common.math.FlexiBigInt;

public class RSAPrivateKeySpec extends java.security.spec.RSAPrivateKeySpec
	implements RSAPrivKeySpecInterface {

    // ****************************************************
    // JCA adapter methods
    // ****************************************************

    public RSAPrivateKeySpec(BigInteger n, BigInteger d) {
	super(n, d);
    }

    /**
     * Create a new RSAPrivateKeySpec out of the given
     * {@link java.security.spec.RSAPrivateKeySpec}.
     * 
     * @param keySpec
     *                the {@link java.security.spec.RSAPrivateKeySpec}
     */
    public RSAPrivateKeySpec(java.security.spec.RSAPrivateKeySpec keySpec) {
	super(keySpec.getModulus(), keySpec.getPrivateExponent());
    }

    // ****************************************************
    // FlexiAPI methods
    // ****************************************************

    public RSAPrivateKeySpec(FlexiBigInt n, FlexiBigInt d) {
	super(n.bigInt, d.bigInt);
    }

    /**
     * @return the modulus n
     */
    public FlexiBigInt getN() {
	return new FlexiBigInt(getModulus());
    }

    /**
     * @return the private exponent d
     */
    public FlexiBigInt getD() {
	return new FlexiBigInt(getPrivateExponent());
    }

}
