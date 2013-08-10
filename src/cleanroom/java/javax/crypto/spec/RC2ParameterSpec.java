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

/**
 * @author Patric Kabus
 * @version "$Id: RC2ParameterSpec.java,v 1.1.1.1 2001/05/15 11:59:09 krprvadm
 *          Exp $"
 */
public class RC2ParameterSpec extends Object implements AlgorithmParameterSpec {
    private byte[] iv_;

    private int effectiveKeyBits_;

    public RC2ParameterSpec(int effectiveKeyBits) {
        effectiveKeyBits_ = effectiveKeyBits;
    }

    public RC2ParameterSpec(int effectiveKeyBits, byte[] iv) {
        this(effectiveKeyBits, iv, 0);
    }

    public RC2ParameterSpec(int effectiveKeyBits, byte[] iv, int offset) {
        if (iv == null) {
            throw new NullPointerException("iv");
        }
        if (iv.length - offset < 8) {
            throw new IllegalArgumentException(
                    "iv buffer too short for given offset");
        }
        effectiveKeyBits_ = effectiveKeyBits;
        iv_ = new byte[8];

        System.arraycopy(iv, offset, iv_, 0, 8);
    }

    public int getEffectiveKeyBits() {
        return effectiveKeyBits_;
    }

    public byte[] getIV() {
        return (byte[]) iv_.clone();
    }
}
