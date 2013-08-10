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
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class KeyAgreement extends Object {
    private KeyAgreementSpi keyAgreeSpi_;

    private Provider provider_;

    private String algorithm_;

    protected KeyAgreement(KeyAgreementSpi keyAgreeSpi, Provider provider,
            String algorithm) {
        if (keyAgreeSpi == null) {
            throw new NullPointerException("keyAgreeSpi");
        }
        if (provider == null) {
            throw new NullPointerException("provider");
        }
        if (algorithm == null) {
            throw new NullPointerException("algorithm");
        }
        keyAgreeSpi_ = keyAgreeSpi;
        provider_ = provider;
        algorithm_ = algorithm;
    }

    public final String getAlgorithm() {
        return algorithm_;
    }

    public static final KeyAgreement getInstance(String algorithm)
            throws NoSuchAlgorithmException {
        Object[] o;

        if (algorithm == null) {
            throw new NullPointerException("algorithm");
        }
        o = Util.getImpl(algorithm, Util.KEY_AGREEMENT);
        return new KeyAgreement((KeyAgreementSpi) o[0], (Provider) o[1],
                algorithm);
    }

    public static final KeyAgreement getInstance(String algorithm,
            String provider) throws NoSuchAlgorithmException,
            NoSuchProviderException {
        Object[] o;

        if (algorithm == null) {
            throw new NullPointerException("algorithm");
        }
        if (provider == null) {
            throw new NullPointerException("provider");
        }
        o = Util.getImpl(algorithm, Util.KEY_AGREEMENT, provider);
        return new KeyAgreement((KeyAgreementSpi) o[0], (Provider) o[1],
                algorithm);
    }

    public final Provider getProvider() {
        return provider_;
    }

    public final void init(Key key) throws InvalidKeyException {
        init(key, new SecureRandom());
    }

    public final void init(Key key, SecureRandom random)
            throws InvalidKeyException {
        keyAgreeSpi_.engineInit(key, random);
    }

    public final void init(Key key, AlgorithmParameterSpec params)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        init(key, params, new SecureRandom());
    }

    public final void init(Key key, AlgorithmParameterSpec params,
            SecureRandom random) throws InvalidKeyException,
            InvalidAlgorithmParameterException {
        if (key == null) {
            throw new NullPointerException("key");
        }
        if (params == null) {
            throw new NullPointerException("params");
        }
        if (random == null) {
            throw new NullPointerException("random");
        }
        keyAgreeSpi_.engineInit(key, params, random);
    }

    public final Key doPhase(Key key, boolean lastPhase)
            throws InvalidKeyException, IllegalStateException {
        if (key == null) {
            throw new NullPointerException("key");
        }
        return keyAgreeSpi_.engineDoPhase(key, lastPhase);
    }

    public final byte[] generateSecret() throws IllegalStateException {
        return keyAgreeSpi_.engineGenerateSecret();
    }

    public final int generateSecret(byte[] sharedSecret, int offset)
            throws IllegalStateException, ShortBufferException {
        if (sharedSecret == null) {
            throw new NullPointerException("sharedSecret");
        }
        if (offset < 0) {
            throw new IllegalArgumentException("offset is <0");
        }
        return keyAgreeSpi_.engineGenerateSecret(sharedSecret, offset);
    }

    public final SecretKey generateSecret(String algorithm)
            throws IllegalStateException, NoSuchAlgorithmException,
            InvalidKeyException {
        if (algorithm == null) {
            throw new NullPointerException("algorithm");
        }
        return keyAgreeSpi_.engineGenerateSecret(algorithm);
    }
}
