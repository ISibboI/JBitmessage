/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.rc5;

import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.common.util.ByteUtils;

/**
 * RC5Key is used to store a symmetric Key for RC5 Encryption/Decryption.
 * 
 * @author Oliver Seiler
 */
public class RC5Key implements SecretKey {

    // the key bytes
    private byte[] keyBytes;

    /**
     * Construct a new RC5 key from the given key bytes
     * 
     * @param keyBytes
     *                the key bytes
     */
    protected RC5Key(byte[] keyBytes) {
	this.keyBytes = ByteUtils.clone(keyBytes);
    }

    /**
     * Return the name of the algorithm the key is used with.
     * 
     * @return "RC5"
     */
    public String getAlgorithm() {
	return "RC5";
    }

    /**
     * Return the encoding format of the key.
     * 
     * @return "RAW"
     */
    public String getFormat() {
	return "RAW";
    }

    /**
     * @return a copy of the key bytes
     */
    public byte[] getEncoded() {
	return ByteUtils.clone(keyBytes);
    }

    /**
     * Compare this key with another object.
     * 
     * @param other
     *                the other object
     * @return the result of the comparison
     */
    public boolean equals(Object other) {
	if (other == null || !(other instanceof RC5Key)) {
	    return false;
	}
	return ByteUtils.equals(keyBytes, ((RC5Key) other).keyBytes);
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
