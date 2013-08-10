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

public class PBEParameterSpec extends Object implements AlgorithmParameterSpec {
    private byte[] salt_;

    private int iterationCount_;

    public PBEParameterSpec(byte[] salt, int iterationCount) {
        if (salt == null) {
            throw new NullPointerException("salt");
        }
        salt_ = (byte[]) salt.clone();
        iterationCount_ = iterationCount;
    }

    public byte[] getSalt() {
        return (byte[]) salt_.clone();
    }

    public int getIterationCount() {
        return iterationCount_;
    }
}
