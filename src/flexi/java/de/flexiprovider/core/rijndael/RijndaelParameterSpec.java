/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.rijndael;

import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.mode.ModeParameterSpec;
import de.flexiprovider.common.util.ByteUtils;

/**
 * This class specifies the parameters used by the Rijndael block cipher.
 * <p>
 * The parameters consist of the block size and an optional initialization
 * vector (IV).
 * <p>
 * Values for block size, as specified in the AES standards, are 128, 192, and
 * 256 bits. The default block size is 128 bits. IVs are used by ciphers in CBC,
 * CFB and OFB mode.
 * 
 * @author Katja Rauch
 * @author Martin Döring
 */
public class RijndaelParameterSpec implements AlgorithmParameterSpec {

    /**
     * The default block size (128 bits)
     */
    public static final int DEFAULT_BLOCK_SIZE = 128;

    /**
     * the block size in bits
     */
    private int blockSize;

    /**
     * the initialization vector
     */
    private byte[] iv;

    /**
     * Construct the default Rijndael parameters without an initialization
     * vector (IV). Set the block size to {@link #DEFAULT_BLOCK_SIZE}.
     */
    public RijndaelParameterSpec() {
	this(DEFAULT_BLOCK_SIZE);
    }

    /**
     * Construct the default Rijndael parameters with the given initialization
     * vector (IV). Set the block size to {@link #DEFAULT_BLOCK_SIZE}.
     * 
     * @param modeParams
     *                the mode parameters containing the IV
     */
    public RijndaelParameterSpec(ModeParameterSpec modeParams) {
	this(DEFAULT_BLOCK_SIZE, modeParams);
    }

    /**
     * Construct new Rijndael parameters from the given block size. If the block
     * size is invalid, the {@link #DEFAULT_BLOCK_SIZE default block size} is
     * chosen.
     * 
     * @param blockSize
     *                the block size (128, 192, or 256 bits)
     */
    public RijndaelParameterSpec(int blockSize) {
	if ((blockSize != 128) && (blockSize != 192) && (blockSize != 256)) {
	    this.blockSize = DEFAULT_BLOCK_SIZE;
	} else {
	    this.blockSize = blockSize;
	}
    }

    /**
     * Construct new Rijndael parameters from the given block size and
     * initialization vector (IV). If the block size is invalid, the
     * {@link #DEFAULT_BLOCK_SIZE default block size} is chosen.
     * 
     * @param blockSize
     *                the block size (128, 192, or 256 bits)
     * @param modeParams
     *                the mode parameters containing the IV
     */
    public RijndaelParameterSpec(int blockSize, ModeParameterSpec modeParams) {
	this(blockSize);
	iv = modeParams.getIV();
    }

    /**
     * @return the block size in bits
     */
    public int getBlockSize() {
	return blockSize;
    }

    /**
     * @return the initialization vector (maybe <tt>null</tt>)
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
	if ((other == null) || !(other instanceof RijndaelParameterSpec)) {
	    return false;
	}
	RijndaelParameterSpec otherSpec = (RijndaelParameterSpec) other;

	return (blockSize == otherSpec.blockSize)
		&& ByteUtils.equals(iv, otherSpec.iv);
    }

    /**
     * @return the hash code of these parameters
     */
    public int hashCode() {
	if (iv == null) {
	    return blockSize;
	}
	return blockSize + iv.hashCode();
    }

}
