/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */
package de.flexiprovider.core.kdf;

import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.util.ByteUtils;
import de.flexiprovider.core.mac.HMac;

/**
 * This class represents parameters for the {@link PBKDF2} key derivation
 * function (OID 1.2.840.113549.2.7) used for passphrase based encryption.
 * 
 * @author Thomas Wahrenbruch
 * @author Martin Döring
 */
public class PBKDF2ParameterSpec implements AlgorithmParameterSpec {

    /**
     * The OID of the default pseudo-random function (HmacWithSHA1)
     */
    public static final String DEFAULT_PRF_OID = HMac.SHA1.OID;

    // the salt
    private byte[] salt = null;

    // the iteration count
    private int iterationCount = 1000;

    // the key size
    private int keySize;

    /**
     * Construct new PBKDF2 parameters from the given salt, iteration count, and
     * key size.
     * 
     * @param salt
     *                the salt
     * @param iterationCount
     *                the iteration count
     * @param keySize
     *                the key size
     */
    public PBKDF2ParameterSpec(byte[] salt, int iterationCount, int keySize) {
	this.salt = ByteUtils.clone(salt);
	this.iterationCount = iterationCount;
	this.keySize = keySize;
    }

    /**
     * @return the salt
     */
    public byte[] getSalt() {
	return salt;
    }

    /**
     * @return the iteration count
     */
    public int getIterationCount() {
	return iterationCount;
    }

    /**
     * @return the key size
     */
    public int getKeySize() {
	return keySize;
    }

    /**
     * @return a human readable form of the parameters
     */
    public String toString() {
	String result = "salt             : " + ByteUtils.toHexString(salt);
	result += "\niteration count: " + iterationCount;
	result += "\nkey size       : " + keySize;
	result += "\nprf OID        : " + DEFAULT_PRF_OID;
	return result;
    }

}
