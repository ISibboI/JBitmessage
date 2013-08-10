/* Copyright 2000 Fraunhofer Gesellschaft
 * Leonrodstr. 54, 80636 Munich, Germany.
 * All rights reserved.
 *
 * You shall use this software only in accordance with
 * the terms of the license agreement you entered into
 * with Fraunhofer Gesellschaft.
 */
package javax.crypto;

public class NullCipher extends Cipher {
    public NullCipher() {
        super(new NullCipherSpi(), null, "");
    }
}
