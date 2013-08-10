/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.md;

import de.flexiprovider.api.MessageDigest;
import de.flexiprovider.common.util.LittleEndianConversions;

/**
 * This class is the base class for all message digests of the MD family ({@link MD4},
 * {@link MD5}, {@link RIPEMD128}, ...).
 * 
 * @author Martin Döring
 */
public abstract class MDFamilyDigest extends MessageDigest {

    // the digest length in bytes
    private int digestLength;

    // buffer used to store bytes for
    private byte[] buffer = new byte[64];

    // count the number of bytes to digest
    private int count;

    /**
     * internal buffer for processing
     */
    protected int[] x = new int[16];

    /**
     * state of the engine
     */
    protected int[] state = null;

    /**
     * Constructor.
     * 
     * @param digestLength
     *                the digest length
     */
    protected MDFamilyDigest(int digestLength) {
	this.digestLength = digestLength;
	reset();
    }

    /**
     * Initialize the function with an initial state.
     * 
     * @param initialState
     *                the initial state
     */
    protected void initMessageDigest(int[] initialState) {
	if (state == null) {
	    state = new int[initialState.length];
	}
	System.arraycopy(initialState, 0, state, 0, initialState.length);
	count = 0;
    }

    /**
     * @return the digest length in bytes.
     */
    public int getDigestLength() {
	return digestLength;
    }

    /**
     * Update the engine with a single byte
     * 
     * @param b
     *                byte to be added.
     */
    public synchronized void update(byte b) {
	buffer[count & 63] = b;
	if ((count & 63) == 63) {
	    // 64 bytes arrived -> time for some processing
	    for (int i = 15; i >= 0; i--) {
		// setup x with converted values from the buffer
		x[i] = LittleEndianConversions.OS2IP(buffer, 4 * i);
	    }
	    processBlock();
	}
	count++;
    }

    /**
     * add a block of data from the array bytes to the message digest. The block
     * starts offset bytes into the array, and is of size length.
     * 
     * @param bytes
     *                byte array to process
     * @param offset
     *                offset into the array to start from
     * @param len
     *                number of bytes to process
     */
    public synchronized void update(byte[] bytes, int offset, int len) {
	// fill up buffer
	while ((len > 0) & ((count & 63) != 0)) {
	    update(bytes[offset++]);
	    len--;
	}

	// return if nothing left to do
	if (len == 0) {
	    return;
	}

	// process 64 byte blocks at once
	while (len >= 64) {
	    for (int i = 0; i <= 15; i++) {
		x[i] = LittleEndianConversions.OS2IP(bytes, offset);
		offset += 4;
	    }
	    count += 64;
	    len -= 64;
	    processBlock();
	}

	// process the remaining bytes
	if (len > 0) {
	    System.arraycopy(bytes, offset, buffer, 0, len);
	    count += len;
	}
    }

    /**
     * this method performs the padding. A single 1-bit is appended and then
     * 0-bits, until only 64 bits are left free in the final block to enter the
     * total length of the entered message.
     */
    protected void padMessageDigest() {
	// bit length = count * 8
	long len = count << 3;

	// do some padding
	update((byte) 0x80); // add single bit
	while ((count & 63) != 56) {
	    update((byte) 0); // fill up with zeros
	}

	// convert byte buffer to int buffer
	for (int i = 0; i < 14; i++) {
	    x[i] = LittleEndianConversions.OS2IP(buffer, 4 * i);
	}

	// add length
	x[14] = (int) (len & 0xffffffff);
	x[15] = (int) ((len >>> 32) & 0xffffffff);

	processBlock();
    }

    /**
     * Compute the hash value of the current block.
     */
    protected abstract void processBlock();

    /**
     * Left rotate the given word by the specified amount.
     * 
     * @param x
     *                the word
     * @param n
     *                the rotation amount
     * @return the rotated word
     */
    protected static int rotateLeft(int x, int n) {
	return (x << n) | (x >>> (32 - n));
    }

}
