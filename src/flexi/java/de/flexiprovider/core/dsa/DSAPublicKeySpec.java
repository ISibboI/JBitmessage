package de.flexiprovider.core.dsa;

import java.math.BigInteger;

import de.flexiprovider.api.keys.KeySpec;
import de.flexiprovider.common.math.FlexiBigInt;

/**
 * This class specifies a DSA public key with its associated parameters.
 * 
 * @see java.security.Key
 * @see java.security.KeyFactory
 * @see KeySpec
 */
public final class DSAPublicKeySpec extends java.security.spec.DSAPublicKeySpec
	implements KeySpec {

    // ****************************************************
    // JCA adapter methods
    // ****************************************************

    /**
     * Create a new DSAPublicKeySpec with the specified parameter values.
     * 
     * @param y
     *                the public key
     * @param p
     *                the prime
     * @param q
     *                the sub-prime
     * @param g
     *                the base
     */
    public DSAPublicKeySpec(BigInteger y, BigInteger p, BigInteger q,
	    BigInteger g) {
	super(y, p, q, g);
    }

    /**
     * Create a new DSAPublicKeySpec out of the given
     * {@link java.security.spec.DSAPublicKeySpec}.
     * 
     * @param keySpec
     *                the {@link java.security.spec.DSAPublicKeySpec}
     */
    public DSAPublicKeySpec(java.security.spec.DSAPublicKeySpec keySpec) {
	super(keySpec.getY(), keySpec.getP(), keySpec.getQ(), keySpec.getG());
    }

    // ****************************************************
    // FlexiAPI methods
    // ****************************************************

    /**
     * Create a new DSAPrivateKeySpec with the specified parameter values.
     * 
     * @param y
     *                the public key
     * @param p
     *                the prime
     * @param q
     *                the sub-prime
     * @param g
     *                the base
     */
    public DSAPublicKeySpec(FlexiBigInt y, FlexiBigInt p, FlexiBigInt q,
	    FlexiBigInt g) {
	super(y.bigInt, p.bigInt, q.bigInt, g.bigInt);
    }

    /**
     * @return the value <tt>y</tt> of the public key
     */
    public FlexiBigInt getValueY() {
	return new FlexiBigInt(getY());
    }

    /**
     * @return the prime <tt>p</tt>
     */
    public FlexiBigInt getPrimeP() {
	return new FlexiBigInt(getP());
    }

    /**
     * @return the sub-prime <tt>q</tt>
     */
    public FlexiBigInt getPrimeQ() {
	return new FlexiBigInt(getQ());
    }

    /**
     * @return the base <tt>g</tt>
     */
    public FlexiBigInt getBaseG() {
	return new FlexiBigInt(getG());
    }

}
