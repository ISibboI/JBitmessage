/* Copyright 2000 Fraunhofer Gesellschaft
 * Leonrodstr. 54, 80636 Munich, Germany.
 * All rights reserved.
 *
 * You shall use this software only in accordance with
 * the terms of the license agreement you entered into
 * with Fraunhofer Gesellschaft.
 */
package javax.crypto.spec;

import java.security.spec.KeySpec;

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
 */
public class PBEKeySpec extends Object implements KeySpec {

    /**
     * The password
     */
    private char[] password;

    /**
     * Create a new PBE key specification.
     * 
     * @param password
     *                the password
     */
    public PBEKeySpec(char[] password) {
	if (password != null) {
	    this.password = (char[]) password.clone();
	}
    }

    /**
     * Get the password character array.
     * 
     * @return The password.
     */
    public final char[] getPassword() {
	if (password != null) {
	    return (char[]) password.clone();
	}
	return null;
    }

}
