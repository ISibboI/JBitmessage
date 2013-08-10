/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.md;

import java.io.ByteArrayOutputStream;

import de.flexiprovider.api.MessageDigest;

/**
 * This class only performs buffering of the input data. No message digest
 * function is applied.
 * 
 * @author Ralf-Philipp Weinmann
 * @author Martin Döring
 */
public final class NullDigest extends MessageDigest {

    private ByteArrayOutputStream buf = new ByteArrayOutputStream();

    /**
     * Get length of message digest. This equals the amount of data accumulated
     * thus far and thus is <b>NOT</b> a fixed value.
     * 
     * @return the length of the message digest
     */
    public int getDigestLength() {
	return buf.size();
    }

    /**
     * Process the given byte.
     * 
     * @param b
     *                the byte to be processed
     */
    public void update(byte b) {
	buf.write(b);
    }

    /**
     * Processes the given number of bytes, supplied in a byte array starting at
     * the given position.
     * 
     * @param input
     *                the byte array containing the input
     * @param inOff
     *                the offset where the input starts
     * @param inLen
     *                the length of the input
     */
    public void update(byte[] input, int inOff, int inLen) {
	buf.write(input, inOff, inLen);
    }

    /**
     * @return the computed digest value
     */
    public byte[] digest() {
	byte[] result = buf.toByteArray();
	reset();
	return result;
    }

    /**
     * Reset message digest to its initial state.
     */
    public void reset() {
	buf.reset();
    }

}
