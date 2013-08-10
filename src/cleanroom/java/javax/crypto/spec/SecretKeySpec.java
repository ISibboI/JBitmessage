/* Copyright 2000 Fraunhofer Gesellschaft
 * Leonrodstr. 54, 80636 Munich, Germany.
 * All rights reserved.
 *
 * You shall use this software only in accordance with
 * the terms of the license agreement you entered into
 * with Fraunhofer Gesellschaft.
 */
package javax.crypto.spec;

import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.SecretKey;

public class SecretKeySpec extends Object implements KeySpec, SecretKey {
    private String algorithm_;

    private byte[] key_;

    public SecretKeySpec(byte[] key, String algorithm) {
        if (key == null) {
            throw new NullPointerException("key");
        }
        if (algorithm == null) {
            throw new NullPointerException("algorithm");
        }
        algorithm_ = algorithm;
        key_ = (byte[]) key.clone();
    }

    public SecretKeySpec(byte[] key, int offset, int len, String algorithm) {
        if (key == null) {
            throw new NullPointerException("key");
        }
        if (algorithm == null) {
            throw new NullPointerException("algorithm");
        }
        if (key.length < offset + len) {
            throw new IllegalArgumentException(
                    "key buffer too small for given length and offset");
        }
        algorithm_ = algorithm;
        key_ = new byte[len];
        System.arraycopy(key, offset, key_, 0, len);
    }

    public String getAlgorithm() {
        return algorithm_;
    }

    public String getFormat() {
        return "RAW";
    }

    public byte[] getEncoded() {
        return (byte[]) key_.clone();
    }

    public int hashCode() {
        int hashCode;
        int i;

        hashCode = 0;
        for (i = 0; i < key_.length; i++) {
            hashCode += key_[i] * 23 + 17;
        }
        hashCode ^= algorithm_.toLowerCase().hashCode();

        return hashCode;
    }

    public boolean equals(Object obj) {
        SecretKey key;

        if (this == obj) {
            return true;
        }
        if (!(obj instanceof SecretKey)) {
            return false;
        }
        key = (SecretKey) obj;
        if (!key.getAlgorithm().equalsIgnoreCase(algorithm_)
                || !Arrays.equals(key.getEncoded(), key_)) {
            return false;
        }
        return true;
    }
}
