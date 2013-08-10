/* Copyright 2000 Fraunhofer Gesellschaft
 * Leonrodstr. 54, 80636 Munich, Germany.
 * All rights reserved.
 *
 * You shall use this software only in accordance with
 * the terms of the license agreement you entered into
 * with Fraunhofer Gesellschaft.
 */
package javax.crypto;

import java.security.Key;

/**
 * A secret (symmetric) key.
 * 
 * <p>
 * This interface contains no methods or constants. Its only purpose is to group
 * (and provide type safety for) secret keys.
 * 
 * <p>
 * Provider implementations of this interface must overwrite the
 * <code>equals</code> and <code>hashCode</code> methods inherited from
 * <code>java.lang.Object</code>, so that secret keys are compared based on
 * their underlying key material and not based on reference.
 * 
 * <p>
 * Keys that implement this interface return the string <code>RAW</code> as
 * their encoding format (see <code>getFormat</code>), and return the raw key
 * bytes as the result of a <code>getEncoded</code> method call. (The
 * <code>getFormat</code> and <code>getEncoded</code> methods are inherited
 * from the <code>java.security.Key</code> parent interface.)
 * 
 * <p>
 * See Also: <CODE>SecretKeyFactory</CODE>, <CODE>Cipher</CODE>
 */
public interface SecretKey extends Key {
}
