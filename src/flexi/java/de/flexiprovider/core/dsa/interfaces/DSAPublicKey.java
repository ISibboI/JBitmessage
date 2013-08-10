package de.flexiprovider.core.dsa.interfaces;

import java.math.BigInteger;

import de.flexiprovider.api.keys.PublicKey;
import de.flexiprovider.common.math.FlexiBigInt;

/**
 * The interface to a DSA public key. DSA (Digital Signature Algorithm) is
 * defined in NIST's FIPS-186.
 * 
 * @see java.security.Signature
 * @see PublicKey
 * @see DSAKey
 * @see DSAPrivateKey
 */
public abstract class DSAPublicKey extends PublicKey implements DSAKey,
	java.security.interfaces.DSAPublicKey {

    // ****************************************************
    // JCA adapter methods
    // ****************************************************

    /**
     * @return the value <tt>y</tt> of the public key
     */
    public final BigInteger getY() {
	return getValueY().bigInt;
    }

    /**
     * @return the DSA parameters
     */
    public final java.security.interfaces.DSAParams getParams() {
	return getParameters();
    }

    // ****************************************************
    // FlexiAPI methods
    // ****************************************************

    /**
     * @return the value <tt>y</tt> of the public key
     */
    public abstract FlexiBigInt getValueY();

}
