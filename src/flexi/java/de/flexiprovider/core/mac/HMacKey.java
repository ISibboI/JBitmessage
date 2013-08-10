/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
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
 * A simple class representing a key for Hmac. The Key is derived by a Key
 * Derivation Function using a hash function (SHA1 or MD5). This class is
 * provided for <a
 * href="http://www.rsasecurity.com/rsalabs/pkcs/pkcs-12/index.html"> PKCS#12</a>.
 * A PFX PDU may be password-integrity-protected. The key for HmacSHA1
 * computation shall be derived by a Key Derivation Function PBKDF1 as described
 * in PKCS #5.
 * 
 * @author Michele Boivin
 */
public class HMacKey extends Object implements SecretKey {

    // the key bytes
    private byte[] keyBytes;

    /**
     * Construct a new Hmac key from the specified key bytes.
     * 
     * @param keyBytes
     *                a byte array containing a key
     */
    protected HMacKey(byte[] keyBytes) {
	this.keyBytes = ByteUtils.clone(keyBytes);
    }

    /**
     * Return the name of the algorithm the key is used with.
     * 
     * @return "Hmac"
     */
    public String getAlgorithm() {
	return "Hmac";
    }

    /**
     * @return a copy of the key bytes
     */
    public byte[] getEncoded() {
	return ByteUtils.clone(keyBytes);
    }

    /**
     * @return the key format
     */
    public String getFormat() {
	return "RAW";
    }

    public boolean equals(Object other) {
	if (other == null || !(other instanceof HMacKey)) {
	    return false;
	}
	return ByteUtils.equals(keyBytes, ((HMacKey) other).keyBytes);
    }

    public int hashCode() {
	return keyBytes.hashCode();
    }

}
