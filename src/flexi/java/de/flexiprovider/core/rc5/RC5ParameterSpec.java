/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */
package de.flexiprovider.core.rc5;

import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.mode.ModeParameterSpec;
import de.flexiprovider.common.util.ByteUtils;

/**
 * This class specifies the parameters for the RC5 Algorithm. The parameters
 * consist of the version number, the number of rounds, the word size, and an
 * optional initialization vector (IV). The block size of RC5 is twice the word
 * size. Values for the number of rounds are 8 to 127, with the default being
 * 12. Values for the word size are 16, 32, and 64 bits, with the default being
 * 32 bits.
 * 
 * @author Oliver Seiler
 * @author Martin Döring
 */
public class RC5ParameterSpec implements AlgorithmParameterSpec {

    /**
     * Constant defining the first version of RC5
     */
    public static final int RC5_v1_0 = 16;

    /**
     * The default number of rounds (12)
     */
    public static final int DEFAULT_NUM_ROUNDS = 12;

    /**
     * The default word size (32 bits)
     */
    public static final int DEFAULT_WORD_SIZE = 32;

    // number of rounds
    private int numRounds;

    // word size in bits
    private int wordSize;

    // initialization vector
    private byte[] iv;

    /**
     * Construct the default RC5 parameters without an IV. The default
     * parameters are:
     * <ul>
     * <li>version: {@link #RC5_v1_0}</li>
     * <li>number of rounds: {@link #DEFAULT_NUM_ROUNDS}</li>
     * <li>word size: {@link #DEFAULT_WORD_SIZE}</li>
     * </ul>
     */
    public RC5ParameterSpec() {
	numRounds = DEFAULT_NUM_ROUNDS;
	wordSize = DEFAULT_WORD_SIZE;
    }

    /**
     * Construct the default RC5 parameters with the given IV. The default
     * parameters are:
     * <ul>
     * <li>version: {@link #RC5_v1_0}</li>
     * <li>number of rounds: {@link #DEFAULT_NUM_ROUNDS}</li>
     * <li>word size: {@link #DEFAULT_WORD_SIZE}</li>
     * </ul>
     * 
     * @param modeParams
     *                the mode parameters containing the IV
     */
    public RC5ParameterSpec(ModeParameterSpec modeParams) {
	this();
	iv = modeParams.getIV();
    }

    /**
     * Construct a parameter set for RC5 from the given number of rounds and
     * word size. Choose version as {@link #RC5_v1_0}. If the number of rounds
     * is invalid, choose {@link #DEFAULT_NUM_ROUNDS}. If the word size is
     * invalid, choose the {@link #DEFAULT_WORD_SIZE}. The block size of RC5 is
     * twice the word size.
     * 
     * @param numRounds
     *                the number of rounds (8...127)
     * @param wordSize
     *                the word size (16, 32, or 64 bits)
     */
    public RC5ParameterSpec(int numRounds, int wordSize) {
	if ((numRounds < 8) || (numRounds > 127)) {
	    this.numRounds = DEFAULT_NUM_ROUNDS;
	} else {
	    this.numRounds = numRounds;
	}

	if ((wordSize != 16) && (wordSize != 32) && (wordSize != 64)) {
	    this.wordSize = DEFAULT_WORD_SIZE;
	} else {
	    this.wordSize = wordSize;
	}
    }

    /**
     * Construct a parameter set for RC5 from the given number of rounds, word
     * size, and initialization vector (IV). Choose version as {@link #RC5_v1_0}.
     * If the number of rounds is invalid, choose {@link #DEFAULT_NUM_ROUNDS}.
     * If the word size is invalid, choose the {@link #DEFAULT_WORD_SIZE}. The
     * block size of RC5 is twice the word size.
     * 
     * @param numRounds
     *                the number of rounds (8...127)
     * @param wordSize
     *                the word size (16, 32, or 64 bits)
     * @param modeParams
     *                the mode parameters containing the IV
     */
    public RC5ParameterSpec(int numRounds, int wordSize,
	    ModeParameterSpec modeParams) {
	this(numRounds, wordSize);
	iv = modeParams.getIV();
    }

    /**
     * @return the version number
     */
    public int getVersion() {
	return RC5_v1_0;
    }

    /**
     * @return the number of rounds
     */
    public int getNumRounds() {
	return numRounds;
    }

    /**
     * @return the word size in bits
     */
    public int getWordSize() {
	return wordSize;
    }

    /**
     * @return a copy of the initialization vector (IV) (maybe <tt>null</tt>)
     */
    public byte[] getIV() {
	return ByteUtils.clone(iv);
    }

    /**
     * Compare these parameters with another object.
     * 
     * @param other
     *                the other object
     * @return the result of the comparison
     */
    public boolean equals(Object other) {
	if ((other == null) || !(other instanceof RC5ParameterSpec)) {
	    return false;
	}
	RC5ParameterSpec otherSpec = (RC5ParameterSpec) other;

	return (numRounds == otherSpec.numRounds)
		&& (wordSize == otherSpec.wordSize)
		&& ByteUtils.equals(iv, otherSpec.iv);
    }

    /**
     * @return the hash code of these parameters
     */
    public int hashCode() {
	int hash = RC5_v1_0 + numRounds + wordSize;
	if (iv != null) {
	    hash += iv.hashCode();
	}
	return hash;
    }

}
