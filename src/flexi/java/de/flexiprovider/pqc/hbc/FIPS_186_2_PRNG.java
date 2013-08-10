package de.flexiprovider.pqc.hbc;

import de.flexiprovider.api.MessageDigest;

/**
 * This class provides random number generation for CMSS.
 * 
 * @author Sebastian Blume
 * @author Martin Döring
 */
public class FIPS_186_2_PRNG implements PRNG {

    // the hash function used for constructing the random numbers
    private MessageDigest md;

    /**
     * Initialize the RNG with the given message digest.
     * 
     * @param md
     *                the message digest for constructing the random numbers
     */
    public void initialize(MessageDigest md) {
	this.md = md;
    }

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
    public byte[] nextSeed(byte[] outSeed) {

	// byte array value "1"
	byte[] one = new byte[outSeed.length];
	one[0] = 1;

	// RAND <-- H(inSeed)
	byte[] rand = md.digest(outSeed);

	// outSeed <-- (1 + inSeed +RAND) mod 2^n
	add(outSeed, rand);
	addOne(outSeed);

	return rand;
    }

    /**
     * Add two values given as byte arrays.
     * 
     * @param a
     *                the first value
     * @param b
     *                the second value
     */
    private static void add(byte[] a, byte[] b) {
	byte carry = 0;
	for (int i = 0; i < a.length; i++) {
	    int temp = (a[i] & 0xff) + (b[i] & 0xff) + carry;
	    a[i] = (byte) temp;
	    carry = (byte) (temp >> 8);
	}
    }

    /**
     * Add one to a value given as byte array.
     * 
     * @param a
     *                the value
     */
    private static void addOne(byte[] a) {
	byte carry = 1;
	for (int i = 0; i < a.length; i++) {
	    int temp = (a[i] & 0xff) + carry;
	    a[i] = (byte) temp;
	    carry = (byte) (temp >> 8);
	}
    }

}
