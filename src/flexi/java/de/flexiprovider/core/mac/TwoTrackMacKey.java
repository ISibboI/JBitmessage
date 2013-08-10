/*
 * Copyright (c) 1998-2007 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.mac;

import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.common.util.ByteUtils;

/**
 * This class implements a key for the TwoTrackMac algorithm.
 * 
 * @author Paul Nguentcheu
 */
public class TwoTrackMacKey implements SecretKey {

    // the key bytes
    private byte[] keyBytes;

    /**
     * Construct a new TwoTrackMac key from the given key bytes.
     * 
     * @param keyBytes
     *                the key bytes
     */
    protected TwoTrackMacKey(byte[] keyBytes) {
	this.keyBytes = ByteUtils.clone(keyBytes);
    }

    /**
     * Return the name of the algorithm the key is used with.
     * 
     * @return "TwoTrackMac"
     */
    public java.lang.String getAlgorithm() {
	return "TwoTrackMac";
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
	if (other == null || !(other instanceof TwoTrackMacKey)) {
	    return false;
	}
	return ByteUtils.equals(keyBytes, ((TwoTrackMacKey) other).keyBytes);
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
