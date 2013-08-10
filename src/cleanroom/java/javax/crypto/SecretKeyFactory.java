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
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class SecretKeyFactory extends Object {
    private SecretKeyFactorySpi keyFacSpi_;

    private Provider provider_;

    private String algorithm_;

    protected SecretKeyFactory(SecretKeyFactorySpi keyFacSpi,
            Provider provider, String algorithm) {
        if (keyFacSpi == null) {
            throw new NullPointerException("keyFacSpi");
        }
        if (provider == null) {
            throw new NullPointerException("provider");
        }
        if (algorithm == null) {
            throw new NullPointerException("algorithm");
        }
        keyFacSpi_ = keyFacSpi;
        provider_ = provider;
        algorithm_ = algorithm;
    }

    public static final SecretKeyFactory getInstance(String algorithm)
            throws NoSuchAlgorithmException {
        Object[] o;

        if (algorithm == null) {
            throw new NullPointerException("algorithm");
        }
        o = Util.getImpl(algorithm, Util.SECRET_KEY_FACTORY);
        return new SecretKeyFactory((SecretKeyFactorySpi) o[0],
                (Provider) o[1], algorithm);
    }

    public static final SecretKeyFactory getInstance(String algorithm,
            String provider) throws NoSuchAlgorithmException,
            NoSuchProviderException {
        Object[] o;

        if (algorithm == null) {
            throw new NullPointerException("algorithm");
        }
        if (provider == null) {
            throw new NullPointerException("provider");
        }
        o = Util.getImpl(algorithm, Util.SECRET_KEY_FACTORY, provider);
        return new SecretKeyFactory((SecretKeyFactorySpi) o[0],
                (Provider) o[1], algorithm);
    }

    public final Provider getProvider() {
        return provider_;
    }

    public final String getAlgorithm() {
        return algorithm_;
    }

    public final SecretKey generateSecret(KeySpec keySpec)
            throws InvalidKeySpecException {
        if (keySpec == null) {
            throw new NullPointerException("keySpec");
        }
        return keyFacSpi_.engineGenerateSecret(keySpec);
    }

    public final KeySpec getKeySpec(SecretKey key, Class keySpec)
            throws InvalidKeySpecException {
        if (key == null) {
            throw new NullPointerException("key");
        }
        if (keySpec == null) {
            throw new NullPointerException("keySpec");
        }
        return keyFacSpi_.engineGetKeySpec(key, keySpec);
    }

    public final SecretKey translateKey(SecretKey key)
            throws InvalidKeyException {
        if (key == null) {
            throw new NullPointerException("key");
        }
        return keyFacSpi_.engineTranslateKey(key);
    }
}
