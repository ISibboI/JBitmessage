/* Copyright 2000 Fraunhofer Gesellschaft
 * Leonrodstr. 54, 80636 Munich, Germany.
 * All rights reserved.
 *
 * You shall use this software only in accordance with
 * the terms of the license agreement you entered into
 * with Fraunhofer Gesellschaft.
 */
package javax.crypto.interfaces;

import java.math.BigInteger;
import java.security.PublicKey;

public abstract interface DHPublicKey extends DHKey, PublicKey {
    BigInteger getY();
}
