package de.flexiprovider.core.dsa.interfaces;

import de.flexiprovider.common.math.FlexiBigInt;

/**
 * Interface to a set of key parameters for DSA (Digital Signature Algorithm),
 * which is defined in NIST's FIPS-186.
 * 
 * @see java.security.interfaces.DSAKey
 * @see java.security.Key
 * @see java.security.Signature
 */
public interface DSAParams extends java.security.interfaces.DSAParams {

    // ****************************************************
    // FlexiAPI methods
    // ****************************************************

    /**
     * @return the prime <tt>p</tt>
     */
    FlexiBigInt getPrimeP();

    /**
     * @return the subprime <tt>q</tt>
     */
    FlexiBigInt getPrimeQ();

    /**
     * @return the base <tt>g</tt>
     */
    FlexiBigInt getBaseG();

}
