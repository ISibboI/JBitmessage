/* Copyright 2000 Fraunhofer Gesellschaft
 * Leonrodstr. 54, 80636 Munich, Germany.
 * All rights reserved.
 *
 * You shall use this software only in accordance with
 * the terms of the license agreement you entered into
 * with Fraunhofer Gesellschaft.
 */
package javax.crypto.spec;

import java.security.InvalidKeyException;
import java.security.spec.KeySpec;

public class DESedeKeySpec extends Object implements KeySpec {
    public static final int DES_EDE_KEY_LEN = 24;

    private byte[] key_;

    public DESedeKeySpec(byte[] key) throws InvalidKeyException {
        this(key, 0);
    }

    public DESedeKeySpec(byte[] key, int offset) throws InvalidKeyException {
        if (key == null) {
            throw new NullPointerException("key");
        }
        if (key.length - offset < 24) {
            throw new InvalidKeyException("key too small for given offset");
        }
        key_ = new byte[24];
        System.arraycopy(key, offset, key_, 0, 24);
    }

    public byte[] getKey() {
        return (byte[]) key_.clone();
    }

    public static boolean isParityAdjusted(byte[] key, int offset)
            throws InvalidKeyException {
        if (key == null) {
            throw new NullPointerException("key");
        }
        if (key.length - offset < 24) {
            throw new InvalidKeyException(
                    "key buffer too short for given offset");
        }
        return DESKeySpec.isParityAdjusted(key, offset)
                && DESKeySpec.isParityAdjusted(key, offset + 8)
                && DESKeySpec.isParityAdjusted(key, offset + 16);
    }
}
