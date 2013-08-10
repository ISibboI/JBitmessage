/* Copyright 2000 Fraunhofer Gesellschaft
 * Leonrodstr. 54, 80636 Munich, Germany.
 * All rights reserved.
 *
 * You shall use this software only in accordance with
 * the terms of the license agreement you entered into
 * with Fraunhofer Gesellschaft.
 */
package javax.crypto;

import java.security.GeneralSecurityException;

public class NoSuchPaddingException extends GeneralSecurityException {
    public NoSuchPaddingException() {
        super();
    }

    public NoSuchPaddingException(String msg) {
        super(msg);
    }
}
