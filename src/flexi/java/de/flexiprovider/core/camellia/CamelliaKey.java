/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.camellia;

import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.common.util.ByteUtils;

/**
 * This class is used for opaquely storing Camellia keys.
 * 
 * @author Ralf-Philipp Weinmann
 */
public class CamelliaKey implements SecretKey {

    /**
     * Key data
     */
    private byte[] keyBytes;

    /**
     * Construct new instance of <tt>CamelliaKey</tt> from an array of key
     * bytes.
     * 
     * @param keyBytes
     *                the key bytes
     */
    protected CamelliaKey(byte[] keyBytes) {
	this.keyBytes = ByteUtils.clone(keyBytes);
    }

    /**
     * Obtain the name of the algorithm this key can be used for.
     * 
     * @return name of the algorithm the key can be used for as a
     *         <tt>String</tt>
     */
    public String getAlgorithm() {
	return "Camellia";
    }

    /**
     * This method will return the format of the key as a String.
     * 
     * @return format of the stored key as a <tt>String</tt>.
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
     * Tests if the argument contains the same key material as <tt>this</tt>
     * 
     * @param other
     *                comparing key material
     * @return <tt>true</tt> if the keys are equal
     */
    public boolean equals(Object other) {
	if (other == null || !(other instanceof CamelliaKey)) {
	    return false;
	}
	CamelliaKey otherKey = (CamelliaKey) other;
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
