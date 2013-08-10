package de.flexiprovider.pqc.hbc;

import de.flexiprovider.api.MessageDigest;

/**
 * This class specifies the interface for random number generators for CMSS.
 * 
 * @author Martin Döring
 */
public interface PRNG {

    /**
     * Initialize the RNG with the given message digest.
     * 
     * @param md
     *                the message digest for constructing the random numbers
     */
    void initialize(MessageDigest md);

    /**
     * Compute the next seed value, return a random byte array, and update the
     * seed to the next value.
     * 
     * @param outSeed
     *                byte array in which
     *                <tt>(1 + inSeed + RAND) mod 2<sup>n</sup>n</tt> will
     *                be stored
     * @return byte array containing <tt>H(inSeed)</tt>
     */
    byte[] nextSeed(byte[] outSeed);

}
