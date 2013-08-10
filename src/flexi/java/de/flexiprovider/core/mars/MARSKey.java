/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.mars;

import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.common.util.ByteUtils;

/**
 * MARSKey is used to store a symmetric key for MARS encryption/decryption.
 * 
 * @author Katja Rauch
 */
public class MARSKey implements SecretKey {

    // the key data
    private byte[] keyBytes;

    /**
     * Construct a new key using the given key data.
     * 
     * @param keyBytes
     *                the key data
     */
    protected MARSKey(byte[] keyBytes) {
	this.keyBytes = ByteUtils.clone(keyBytes);
    }

    /**
     * @return the name of the algorithm the key is used for
     */
    public String getAlgorithm() {
	return "MARS";
    }

    /**
     * @return the format of the encoded key
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
     * Tests if the argument contains the same key material as <tt>this</tt>.
     * 
     * @param other
     *                comparing key material
     * @return <tt>true</tt> if the keys are equal
     */
    public boolean equals(Object other) {
	if ((other == null) || !(other instanceof MARSKey)) {
	    return false;
	}
	return ByteUtils.equals(keyBytes, ((MARSKey) other).keyBytes);
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
