/*
 * Copyright (c) 1998-2008 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */
package de.flexiprovider.ec.keys;

import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.common.math.FlexiBigInt;

/**
 * This class implements an EC secret key.
 * 
 * @author Jochen Hechler
 * @author Marcus St&ouml;gbauer
 */
public class ECSecretKey implements SecretKey {

    // the private key s, 1 < s < r.
    private FlexiBigInt mS;

    /**
     * Construct a new EC secret key.
     * 
     * @param s
     *                the {@link FlexiBigInt} that represents the private key
     */
    public ECSecretKey(FlexiBigInt s) {
	mS = s;
    }

    /**
     * Return the name of the algorithm this key is used with.
     * 
     * @return "EC"
     */
    public String getAlgorithm() {
	return "EC";
    }

    /**
     * @return the key material of this secret key
     */
    public byte[] getEncoded() {
	return mS.toByteArray();
    }

    /**
     * Returns the name of the encoding format for this secret key.
     * 
     * @return "RAW"
     */
    public String getFormat() {
	return "RAW";
    }

    /**
     * @return the private key s
     */
    public FlexiBigInt getS() {
	return mS;
    }

    public boolean equals(Object other) {
	if (!(other instanceof ECSecretKey)) {
	    return false;
	}

	return mS.equals(((ECSecretKey) other).mS);
    }

    public int hashCode() {
	return mS.hashCode();
    }

}
