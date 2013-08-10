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
import java.security.spec.AlgorithmParameterSpec;

public class DHParameterSpec extends Object implements AlgorithmParameterSpec {
    private BigInteger g_;

    private BigInteger p_;

    private int l_;

    public DHParameterSpec(BigInteger p, BigInteger g) {
        if (p == null) {
            throw new NullPointerException("p");
        }
        if (g == null) {
            throw new NullPointerException("g");
        }
        p_ = p;
        g_ = g;
        l_ = 0;
    }

    public DHParameterSpec(BigInteger p, BigInteger g, int l) {
        if (p == null) {
            throw new NullPointerException("p");
        }
        if (g == null) {
            throw new NullPointerException("g");
        }
        p_ = p;
        g_ = g;
        l_ = l;
    }

    public BigInteger getP() {
        return p_;
    }

    public BigInteger getG() {
        return g_;
    }

    public int getL() {
        return l_;
    }
}
