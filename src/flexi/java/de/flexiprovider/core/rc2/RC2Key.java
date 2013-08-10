/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.rc2;

import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.common.util.ByteUtils;

/**
 * RC2Key is used to store a symmetric Key for RC2 Encryption/Decryption.
 * 
 * @author Oliver Seiler
 */
public class RC2Key implements SecretKey {

    /**
     * This array is used to store the key data
     */
    private byte[] keyBytes;

    /**
     * Construct a new RC2 key using the supplied key data.
     * 
     * @param keyBytes
     *                the key data
     */
    protected RC2Key(byte[] keyBytes) {
	this.keyBytes = ByteUtils.clone(keyBytes);
    }

    /**
     * Return the name of the algorithm the key is used for.
     * 
     * @return "RC2"
     */
    public String getAlgorithm() {
	return "RC2";
    }

    /**
     * Return the format of the stored key.
     * 
     * @return "RAW"
     */
    public String getFormat() {
	return "RAW";
    }

    /**
     * @return a copy of the stored key
     */
    public byte[] getEncoded() {
	return ByteUtils.clone(keyBytes);
    }

    /**
     * Tests if the argument contains the same key material as <tt>this</tt>
     * 
     * @param other
     *                comparing key material
     * @return <tt>true</tt> if the keys are equal
     */
    public boolean equals(Object other) {
	if (other == null || !(other instanceof RC2Key)) {
	    return false;
	}
	RC2Key otherKey = (RC2Key) other;
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
