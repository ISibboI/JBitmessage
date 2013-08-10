package de.flexiprovider.core.pbe;

import de.flexiprovider.api.keys.KeySpec;

/**
 * A specification for a password-based key, used for password-based encryption
 * (PBE).
 * <p>
 * Examples of password-based encryption algorithms include:
 * 
 * <ul>
 * <li><a href="http://www.rsasecurity.com/rsalabs/pkcs/pkcs-5/">PKCS #5 -
 * Password-Based Cryptography Standard</a></li>
 * <li><a href="http://www.rsasecurity.com/rsalabs/pkcs/pkcs-12/">PKCS #12 -
 * Personal Information Exchange Syntax Standard</a></li>
 * </ul>
 * 
 * @see PBEParameterSpec
 */
public class PBEKeySpec extends javax.crypto.spec.PBEKeySpec implements KeySpec {

    // ****************************************************
    // JCA adapter methods
    // ****************************************************

    /**
     * Construct a new PBE key specification out of the given
     * {@link javax.crypto.spec.PBEKeySpec}.
     * 
     * @param javaSpec
     *                the {@link javax.crypto.spec.PBEKeySpec}
     */
    public PBEKeySpec(javax.crypto.spec.PBEKeySpec javaSpec) {
	super(javaSpec.getPassword());
    }

    // ****************************************************
    // FlexiAPI methods
    // ****************************************************

    /**
     * Construct a new PBE key specification.
     * 
     * @param password
     *                the password
     */
    public PBEKeySpec(char[] password) {
	super(password);
    }

}
