package de.flexiprovider.pqc.hbc.gmss;

import de.flexiprovider.api.MessageDigest;
import de.flexiprovider.common.math.FlexiBigInt;

/**
 * This class provides a PRNG for GMSS, using FlexiBigInts
 * 
 * @author Sebastian Blume, Michael Schneider
 */
public class GMSSRandomBigInt {

    /**
     * Initial FlexiBigInt from where randomizer starts
     */
    private FlexiBigInt seed;

    /**
     * Hash function for the construction of the authentication trees
     */
    private MessageDigest messDigestTree;

    /**
     * @param messDigestTree
     */
    public GMSSRandomBigInt(MessageDigest messDigestTree) {

	this.messDigestTree = messDigestTree;

    }

    /**
     * sets seed as initial value
     * 
     * @param seed
     *                the seed to set as initial value
     */
    public void setSeed(byte[] seed) {
	this.seed = new FlexiBigInt(seed);

    }

    /**
     * computes the next value, returns a random byte array and sets outseed to
     * the next value
     * 
     * @param outseed
     *                random byte array
     * @return next random value
     */
    public byte[] nextSeed(byte[] outseed) {
	byte[] temp;
	// byte array value "1"

	// RAND <-- H(SEEDin)
	byte[] rand = new byte[outseed.length];
	messDigestTree.update(seed.toByteArray());
	rand = messDigestTree.digest();
	FlexiBigInt randBig = new FlexiBigInt(rand);
	// SEEDout <-- (1 + SEEDin +RAND) mod 2^n
	// int mdLength = messDigestTree.getDigestLength();
	seed = (randBig.add(seed)).add(FlexiBigInt.ONE);
	temp = seed.toByteArray();
	System.arraycopy(temp, 0, outseed, 0, outseed.length);
	seed = new FlexiBigInt(outseed);
	return rand;
    }

}
