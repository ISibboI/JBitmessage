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

public class DESKeySpec extends Object implements KeySpec {
    public static final int DES_KEY_LEN = 8;

    private static final byte[][] WEAK_KEYS = { { 1, 1, 1, 1, 1, 1, 1, 1 },
            { -2, -2, -2, -2, -2, -2, -2, -2 },
            { 31, 31, 31, 31, 31, 31, 31, 31 },
            { -32, -32, -32, -32, -32, -32, -32, -32 },
            { 1, -2, 1, -2, 1, -2, 1, -2 },
            { 31, -32, 31, -32, 14, -15, 14, -15 },
            { 1, -32, 1, -32, 1, -15, 1, -15 },
            { 31, -2, 31, -2, 14, -2, 14, -2 }, { 1, 31, 1, 31, 1, 14, 1, 14 },
            { -32, -2, -32, -2, -15, -2, -15, -2 },
            { -2, 1, -2, 1, -2, 1, -2, 1 },
            { -32, 31, -32, 31, -15, 14, -15, 14 },
            { -32, 1, -32, 1, -15, 1, -15, 1 },
            { -2, 31, -2, 31, -2, 14, -2, 14 }, { 31, 1, 31, 1, 14, 1, 14, 1 },
            { -2, -32, -2, -32, -2, -15, -2, -15 } };

    private byte[] key_;

    public DESKeySpec(byte[] key) throws InvalidKeyException {
        this(key, 0);
    }

    public DESKeySpec(byte[] key, int offset) throws InvalidKeyException {
        if (key == null) {
            throw new NullPointerException("key");
        }
        if (key.length - offset < 8) {
            throw new InvalidKeyException("key too small for given offset");
        }
        key_ = new byte[8];
        System.arraycopy(key, offset, key_, 0, 8);
    }

    public byte[] getKey() {
        return (byte[]) key_.clone();
    }

    public static boolean isParityAdjusted(byte[] key, int offset)
            throws InvalidKeyException {
        int count;
        int i;
        int j;

        if (key == null) {
            throw new NullPointerException("key");
        }
        if (key.length - offset < 8) {
            throw new InvalidKeyException("key too small for given offset");
        }
        for (i = offset; i < (offset + 8); i++) {
            count = 0;
            for (j = 0; j < 8; j++) {
                count += (key[i] >>> j) % 2;
            }
            if (count % 2 == 0) {
                return false;
            }
        }
        return true;
    }

    public static boolean isWeak(byte[] key, int offset)
            throws InvalidKeyException {
        boolean equal;
        int i;
        int j;

        if (key == null) {
            throw new NullPointerException("key");
        }
        if (key.length - offset < 8) {
            throw new InvalidKeyException("key too small for given offset");
        }
        for (i = 0; i < WEAK_KEYS.length; i++) {
            j = 0;
            equal = true;
            while (equal) {
                if (WEAK_KEYS[i][j] != key[j]) {
                    equal = false;
                } else {
                    if (j == 7) {
                        return true;
                    }
                    j++;
                }
            }
        }
        return false;
    }
}
