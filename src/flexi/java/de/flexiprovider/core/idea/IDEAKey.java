/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.idea;

import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.common.util.ByteUtils;

/**
 * IDEAKey is used to store a symmetric Key for IDEA Encryption/Decryption.
 * 
 * @author Ralph Kuhnert
 * @author Anders Adamson
 */
public class IDEAKey implements SecretKey {

    private byte[] keyBytes;

    /**
     * Constructor. Copy the key bytes.
     * 
     * @param keyBytes
     *                the key bytes
     */
    protected IDEAKey(byte[] keyBytes) {
	this.keyBytes = ByteUtils.clone(keyBytes);
    }

    /**
     * returns the algorithm for this key.
     * 
     * @return the string "IDEA"
     */
    public String getAlgorithm() {
	return "IDEA";
    }

    /**
     * @return a copy of the key bytes
     */
    public byte[] getEncoded() {
	return ByteUtils.clone(keyBytes);
    }

    /**
     * returns the format for this key.
     * 
     * @return the string "RAW"
     */
    public String getFormat() {
	return "RAW";
    }

    /**
     * Tests if the argument contains the same key material as <tt>this</tt>
     * 
     * @param other
     *                comparing key material
     * @return <tt>true</tt> if the keys are equal
     */
    public boolean equals(Object other) {
	if (other == null || !(other instanceof IDEAKey)) {
	    return false;
	}
	IDEAKey otherKey = (IDEAKey) other;
	return ByteUtils.equals(keyBytes, otherKey.keyBytes);
    }

    /**
     * @return the hash code of this key
     */
    public int hashCode() {
	int result = 1;
	for (int i = 0; i < keyBytes.length; i++) {
	    result = 31 * result + keyBytes[i];
	}

	return result;
    }

}
