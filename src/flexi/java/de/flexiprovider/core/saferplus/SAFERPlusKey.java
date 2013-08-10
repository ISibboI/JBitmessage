/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.saferplus;

import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.common.util.ByteUtils;

/**
 * This Class provides a Key for the algorithm SAFER+. It manages the
 * keymaterial and assures that Instances of SAFERPlusKey may be compared and
 * hashed according to the value of the key.
 * 
 * @author Martin Strese
 * @author Marcus Lippert
 */
public class SAFERPlusKey implements SecretKey {

    // the key bytes
    private byte[] keyBytes;

    /**
     * Construct a new SAFER+ key from the given key bytes.
     * 
     * @param keyBytes
     *                the key bytes
     */
    protected SAFERPlusKey(byte[] keyBytes) {
	this.keyBytes = ByteUtils.clone(keyBytes);
    }

    /**
     * Return the name of the algorithm the key is used with.
     * 
     * @return "SAFER+"
     */
    public java.lang.String getAlgorithm() {
	return "SAFER+";
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
	if (other == null || !(other instanceof SAFERPlusKey)) {
	    return false;
	}
	return ByteUtils.equals(keyBytes, ((SAFERPlusKey) other).keyBytes);
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
