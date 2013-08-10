/*
 * Created on Jul 2, 2005
 *
 * TODO To change the template for this generated file go to
 * Window - Preferences - Java - Code Style - Code Templates
 */
package de.flexiprovider.pqc.ots.merkle;

import de.flexiprovider.api.parameters.AlgorithmParameterSpec;

/**
 * This class provides the specification of the parameters used by the
 * {@link MerkleOTSKeyPairGenerator}.
 * 
 * @author Elena Klintsevich
 */
public class MerkleOTSKeyGenParameterSpec implements AlgorithmParameterSpec {

    // the seed for the PRNG
    private byte[] seed;

    /**
     * Construct new MerkleOTS parameters from the given seed for the PRNG.
     * 
     * @param seed
     *                the seed
     */
    public MerkleOTSKeyGenParameterSpec(byte[] seed) {
	this.seed = seed;
    }

    /**
     * @return the seed for the PRNG
     */
    public byte[] getSeed() {
	return seed;
    }

}
