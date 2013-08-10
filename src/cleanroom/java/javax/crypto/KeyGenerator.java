/* Copyright 2000 Fraunhofer Gesellschaft
 * Leonrodstr. 54, 80636 Munich, Germany.
 * All rights reserved.
 *
 * You shall use this software only in accordance with
 * the terms of the license agreement you entered into
 * with Fraunhofer Gesellschaft.
 */
package javax.crypto;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class KeyGenerator extends Object {
    private KeyGeneratorSpi keyGenSpi_;

    private Provider provider_;

    private String algorithm_;

    protected KeyGenerator(KeyGeneratorSpi keyGenSpi, Provider provider,
            String algorithm) {
        if (keyGenSpi == null) {
            throw new NullPointerException("keyGenSpi");
        }
        if (provider == null) {
            throw new NullPointerException("provider");
        }
        if (algorithm == null) {
            throw new NullPointerException("algorithm");
        }
        keyGenSpi_ = keyGenSpi;
        provider_ = provider;
        algorithm_ = algorithm;
    }

    public final String getAlgorithm() {
        return algorithm_;
    }

    public static final KeyGenerator getInstance(String algorithm)
            throws NoSuchAlgorithmException {
        Object[] o;

        if (algorithm == null) {
            throw new NullPointerException("algorithm");
        }
        o = Util.getImpl(algorithm, Util.KEY_GENERATOR);
        return new KeyGenerator((KeyGeneratorSpi) o[0], (Provider) o[1],
                algorithm);
    }

    public static final KeyGenerator getInstance(String algorithm,
            String provider) throws NoSuchAlgorithmException,
            NoSuchProviderException {
        Object[] o;

        if (algorithm == null) {
            throw new NullPointerException("algorithm");
        }
        if (provider == null) {
            throw new NullPointerException("provider");
        }
        o = Util.getImpl(algorithm, Util.KEY_GENERATOR, provider);
        return new KeyGenerator((KeyGeneratorSpi) o[0], (Provider) o[1],
                algorithm);
    }

    public final Provider getProvider() {
        return provider_;
    }

    public final void init(SecureRandom random) {
        if (random == null) {
            throw new NullPointerException("random");
        }
        keyGenSpi_.engineInit(random);
    }

    public final void init(AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException {
        init(params, new SecureRandom());
    }

    public final void init(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (params == null) {
            throw new NullPointerException("params");
        }
        if (random == null) {
            throw new NullPointerException("random");
        }
        keyGenSpi_.engineInit(params, random);
    }

    public final void init(int keysize) {
        init(keysize, new SecureRandom());
    }

    public final void init(int keysize, SecureRandom random) {
        if (random == null) {
            throw new NullPointerException("random");
        }
        keyGenSpi_.engineInit(keysize, random);
    }

    public final SecretKey generateKey() {
        return keyGenSpi_.engineGenerateKey();
    }
}
