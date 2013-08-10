/* Copyright 2000 Fraunhofer Gesellschaft
 * Leonrodstr. 54, 80636 Munich, Germany.
 * All rights reserved.
 *
 * You shall use this software only in accordance with
 * the terms of the license agreement you entered into
 * with Fraunhofer Gesellschaft.
 */
package javax.crypto.spec;

import java.security.spec.AlgorithmParameterSpec;

public class DHGenParameterSpec extends Object implements
        AlgorithmParameterSpec {
    private int primeSize_;

    private int exponentSize_;

    public DHGenParameterSpec(int primeSize, int exponentSize) {
        primeSize_ = primeSize;
        exponentSize_ = exponentSize;
    }

    public int getPrimeSize() {
        return primeSize_;
    }

    public int getExponentSize() {
        return exponentSize_;
    }
}
