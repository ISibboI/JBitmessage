/*
 * Copyright (c) 1998-2007 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.misty1;

import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.common.util.ByteUtils;

/**
 * Misty-1 Key is used to store a symmetric key for Misty-1
 * encryption/decryption.
 * 
 * @author Paul Nguentcheu
 */
public class Misty1Key implements SecretKey {

    // the key bytes
    private byte[] keyBytes;

    /**
     * Constructs a new Misty1 key from the given key bytes.
     * 
     * @param keyBytes
     *                the key bytes
     */
    protected Misty1Key(byte[] keyBytes) {
	this.keyBytes = ByteUtils.clone(keyBytes);
    }

    /**
     * Return the name of the algorithm the key is used with.
     * 
     * @return "Misty1"
     */
    public String getAlgorithm() {
	return "Misty1";
    }

    /**
     * @return a copy of the key bytes
     */
    public byte[] getEncoded() {
	return ByteUtils.clone(keyBytes);
    }

    /**
     * Returns the name of the primary encoding format of this key, which is
     * actually RAW (array of bytes)
     * 
     * @return the String "RAW"
     */
    public String getFormat() {
	return "RAW";
    }

    /**
     * Tests if the argument contains the same key material as <code>this</code>
     * 
     * @param other
     *                another object
     * @return <code>true</code> if the keys are equal
     */
    public boolean equals(Object other) {
	if (other == null || !(other instanceof Misty1Key)) {
	    return false;
	}
	Misty1Key otherKey = (Misty1Key) other;
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
