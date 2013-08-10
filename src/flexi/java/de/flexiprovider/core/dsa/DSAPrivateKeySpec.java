package de.flexiprovider.core.dsa;

import java.math.BigInteger;

import de.flexiprovider.api.keys.KeySpec;
import de.flexiprovider.common.math.FlexiBigInt;

/**
 * This class specifies a DSA private key with its associated parameters.
 * 
 * @see java.security.Key
 * @see java.security.KeyFactory
 * @see KeySpec
 */
public final class DSAPrivateKeySpec extends
	java.security.spec.DSAPrivateKeySpec implements KeySpec {

    // ****************************************************
    // JCA adapter methods
    // ****************************************************

    /**
     * Create a new DSAPrivateKeySpec with the specified parameter values.
     * 
     * @param x
     *                the private key
     * @param p
     *                the prime
     * @param q
     *                the sub-prime
     * @param g
     *                the base
     */
    public DSAPrivateKeySpec(BigInteger x, BigInteger p, BigInteger q,
	    BigInteger g) {
	super(x, p, q, g);
    }

    /**
     * Create a new DSAPrivateKeySpec out of the given
     * {@link java.security.spec.DSAPrivateKeySpec}.
     * 
     * @param keySpec
     *                the {@link java.security.spec.DSAPrivateKeySpec}
     */
    public DSAPrivateKeySpec(java.security.spec.DSAPrivateKeySpec keySpec) {
	super(keySpec.getX(), keySpec.getP(), keySpec.getQ(), keySpec.getG());
    }

    // ****************************************************
    // FlexiAPI methods
    // ****************************************************

    /**
     * Create a new DSAPrivateKeySpec with the specified parameter values.
     * 
     * @param x
     *                the private key
     * @param p
     *                the prime
     * @param q
     *                the sub-prime
     * @param g
     *                the base
     */
    public DSAPrivateKeySpec(FlexiBigInt x, FlexiBigInt p, FlexiBigInt q,
	    FlexiBigInt g) {
	super(x.bigInt, p.bigInt, q.bigInt, g.bigInt);
    }

    /**
     * @return the private key <tt>x</tt>.
     */
    public FlexiBigInt getValueX() {
	return new FlexiBigInt(getX());
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
