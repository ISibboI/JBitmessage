/* Copyright 2000 Fraunhofer Gesellschaft
 * Leonrodstr. 54, 80636 Munich, Germany.
 * All rights reserved.
 *
 * You shall use this software only in accordance with
 * the terms of the license agreement you entered into
 * with Fraunhofer Gesellschaft.
 */
package javax.crypto;

import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public abstract class SecretKeyFactorySpi extends Object {
    public SecretKeyFactorySpi() {
    }

    protected abstract SecretKey engineGenerateSecret(KeySpec keySpec)
            throws InvalidKeySpecException;

    protected abstract KeySpec engineGetKeySpec(SecretKey key, Class keySpec)
            throws InvalidKeySpecException;

    protected abstract SecretKey engineTranslateKey(SecretKey key)
            throws InvalidKeyException;
}
