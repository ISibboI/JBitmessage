/*
 * Copyright (c) 1998-2007 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.shacal2;

import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.common.util.ByteUtils;

/**
 * Shacal2Key is used to store a symmetric key for Shacal2
 * encryption/decryption.
 * 
 * @author Paul Nguentcheu
 */
public class Shacal2Key implements SecretKey {

    // the key bytes
    private byte[] keyBytes;

    /**
     * Construct a new Shacal2 key from the given key bytes.
     * 
     * @param keyBytes
     *                the key bytes
     */
    protected Shacal2Key(byte[] keyBytes) {
	this.keyBytes = ByteUtils.clone(keyBytes);
    }

    /**
     * Return the name of the algorithm the key is used with.
     * 
     * @return "Shacal2"
     */
    public java.lang.String getAlgorithm() {
	return "Shacal2";
    }

    /**
     * @return a copy of the key bytes
     */
    public byte[] getEncoded() {
	return ByteUtils.clone(keyBytes);
    }

    /**
     * Return the encoding format of this key.
     * 
     * @return "RAW"
     */
    public java.lang.String getFormat() {
	return "RAW";
    }

    /**
     * Compare this key with another object.
     * 
     * @param other
     *                the other object
     * @return the result of the comparison
     */
    public boolean equals(Object other) {
	if (other == null || !(other instanceof Shacal2Key)) {
	    return false;
	}
	return ByteUtils.equals(keyBytes, ((Shacal2Key) other).keyBytes);
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
