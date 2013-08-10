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
 * This class implements a key for the CMAC-algorithm.
 * 
 * @author Paul Nguentcheu
 */
public class CMacKey implements SecretKey {

    /**
     * array used to store the key data.
     */
    private byte[] keyBytes = null;

    /**
     * Constructor of a CMacKey
     * 
     * @param keyBytes
     *                the key bytes
     */
    protected CMacKey(byte[] keyBytes) {
	this.keyBytes = ByteUtils.clone(keyBytes);
    }

    /**
     * Return the name of the algorithm.
     * 
     * @return "Cmac"
     */
    public String getAlgorithm() {
	return "Cmac";
    }

    /**
     * @return a copy of the key bytes
     */
    public byte[] getEncoded() {
	return ByteUtils.clone(keyBytes);

    }

    /**
     * Returns the format of the key (RAW)
     * 
     * @return the format of the key (RAW)
     */
    public String getFormat() {
	return "RAW";
    }

}
