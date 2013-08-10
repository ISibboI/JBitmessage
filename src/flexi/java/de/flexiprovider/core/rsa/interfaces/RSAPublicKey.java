package de.flexiprovider.core.rsa.interfaces;

import java.math.BigInteger;

import de.flexiprovider.api.keys.PublicKey;
import de.flexiprovider.common.math.FlexiBigInt;

public abstract class RSAPublicKey extends PublicKey implements RSAKey,
	java.security.interfaces.RSAPublicKey {

    // ****************************************************
    // JCA adapter methods
    // ****************************************************

    /**
     * @return the modulus n
     */
    public final BigInteger getModulus() {
	return getN().bigInt;
    }

    /**
     * @return the public exponent e
     */
    public final BigInteger getPublicExponent() {
	return getE().bigInt;
    }

    // ****************************************************
    // FlexiAPI methods
    // ****************************************************

    /**
     * @return name of the algorithm - "RSA"
     */
    public final String getAlgorithm() {
	return "RSA";
    }

    /**
     * @return the public exponent e
     */
    public abstract FlexiBigInt getE();

}
