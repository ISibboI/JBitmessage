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

public class DHPrivateKeySpec extends Object implements KeySpec {
    private BigInteger g_;

    private BigInteger p_;

    private BigInteger x_;

    public DHPrivateKeySpec(BigInteger x, BigInteger p, BigInteger g) {
        if (x == null) {
            throw new NullPointerException("x");
        }
        if (p == null) {
            throw new NullPointerException("p");
        }
        if (g == null) {
            throw new NullPointerException("g");
        }
        x_ = x;
        p_ = p;
        g_ = g;
    }

    public BigInteger getG() {
        return g_;
    }

    public BigInteger getP() {
        return p_;
    }

    public BigInteger getX() {
        return x_;
    }
}
