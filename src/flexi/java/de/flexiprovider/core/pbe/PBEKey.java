/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.pbe;

import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.common.util.CharUtils;

/**
 * A simple class representing a key for PBE (Passphrase Based Encryption).
 * 
 * @author Thomas Wahrenbruch
 */
public class PBEKey implements SecretKey {

    // the key data
    private char[] keyChars;

    /**
     * Construct a new PBEKey with the specified chars.
     * 
     * @param keyChars
     *                the key chars
     */
    protected PBEKey(char[] keyChars) {
	this.keyChars = CharUtils.clone(keyChars);
    }

    /**
     * Returns the name of the algorithm the key is used with.
     * 
     * @return "PBE"
     */
    public String getAlgorithm() {
	return "PBE";
    }

    /**
     * @return the key chars converted into a byte array
     */
    public byte[] getEncoded() {
    	return CharUtils.toByteArrayForPBE(keyChars);
    }

    /**
     * Return the encoding format of the key.
     * 
     * @return "RAW-BMP"
     */
    public String getFormat() {
    	return "RAW-BMP";
    }

    /**
     * @return a copy of the key chars
     */
    public char[] getKey() {
	return CharUtils.clone(keyChars);
    }

}
