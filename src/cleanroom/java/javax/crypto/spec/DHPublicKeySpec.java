/* Copyright 2000 Fraunhofer Gesellschaft
 * Leonrodstr. 54, 80636 Munich, Germany.
 * All rights reserved.
 *
 * You shall use this software only in accordance with
 * the terms of the license agreement you entered into
 * with Fraunhofer Gesellschaft.
 */
package javax.crypto.spec;

import java.math.BigInteger;
import java.security.spec.KeySpec;

public class DHPublicKeySpec extends Object implements KeySpec {
    private BigInteger g_;

    private BigInteger p_;

    private BigInteger y_;

    public DHPublicKeySpec(BigInteger y, BigInteger p, BigInteger g) {
        if (y == null) {
            throw new NullPointerException("y");
        }
        if (p == null) {
            throw new NullPointerException("p");
        }
        if (g == null) {
            throw new NullPointerException("g");
        }
        y_ = y;
        p_ = p;
        g_ = g;
    }

    public BigInteger getG() {
        return g_;
    }

    public BigInteger getP() {
        return p_;
    }

    public BigInteger getY() {
        return y_;
    }
}
