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
import java.security.spec.AlgorithmParameterSpec;

public class Mac extends Object {
    private Provider provider_;

    private boolean init_;

    private String algorithm_;

    private MacSpi macSpi_;

    protected Mac(MacSpi macSpi, Provider provider, String algorithm) {
        if (macSpi == null) {
            throw new NullPointerException("macSpi");
        }
        if (provider == null) {
            throw new NullPointerException("provider");
        }
        if (algorithm == null) {
            throw new NullPointerException("algorithm");
        }
        macSpi_ = macSpi;
        provider_ = provider;
        algorithm_ = algorithm;
        init_ = false;
    }

    public final String getAlgorithm() {
        return algorithm_;
    }

    public static final Mac getInstance(String algorithm)
            throws NoSuchAlgorithmException {
        Object[] o;

        if (algorithm == null) {
            throw new NullPointerException("algorithm");
        }
        o = Util.getImpl(algorithm, Util.MAC);
        return new Mac((MacSpi) o[0], (Provider) o[1], algorithm);
    }

    public static final Mac getInstance(String algorithm, String provider)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        Object[] o;

        if (algorithm == null) {
            throw new NullPointerException("algorithm");
        }
        if (provider == null) {
            throw new NullPointerException("provider");
        }
        o = Util.getImpl(algorithm, Util.MAC, provider);
        return new Mac((MacSpi) o[0], (Provider) o[1], algorithm);
    }

    public final Provider getProvider() {
        return provider_;
    }

    public final int getMacLength() {
        return macSpi_.engineGetMacLength();
    }

    public final void init(Key key) throws InvalidKeyException {
        try {
            init(key, null);
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }

    public final void init(Key key, AlgorithmParameterSpec params)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (key == null) {
            throw new NullPointerException("key");
        }
        /* params may be null, see above */
        macSpi_.engineInit(key, params);
        init_ = true;
    }

    public final void update(byte input) throws IllegalStateException {
        if (!init_) {
            throw new IllegalStateException("not initialised");
        }
        macSpi_.engineUpdate(input);
    }

    public final void update(byte[] input) throws IllegalStateException {
        if (input == null) {
            throw new NullPointerException("input");
        }
        update(input, 0, input.length);
    }

    public final void update(byte[] input, int offset, int len)
            throws IllegalStateException {
        if (!init_) {
            throw new IllegalStateException("not initialised");
        }
        if (input == null) {
            throw new NullPointerException("input");
        }
        if (offset < 0) {
            throw new IllegalArgumentException("offset is <0");
        }
        if (len > (input.length - offset)) {
            throw new ArrayIndexOutOfBoundsException(
                    "input buffer too small for given length and offset");
        }
        macSpi_.engineUpdate(input, offset, len);
    }

    public final byte[] doFinal() throws IllegalStateException {
        if (!init_) {
            throw new IllegalStateException("not initialised");
        }
        return macSpi_.engineDoFinal();
    }

    public final void doFinal(byte[] output, int outOffset)
            throws ShortBufferException, IllegalStateException {
        byte[] buf;

        if (!init_) {
            throw new IllegalStateException("not initialised");
        }
        if (output == null) {
            throw new NullPointerException("output");
        }
        if (outOffset < 0) {
            throw new IllegalArgumentException("outOffset is <0");
        }
        if (output.length <= outOffset) {
            throw new ArrayIndexOutOfBoundsException(
                    "output buffer too small for given offset");
        }
        buf = macSpi_.engineDoFinal();
        if (output.length < (buf.length + outOffset)) {
            throw new ShortBufferException(
                    "buffer too small: cannot place result at given offset");
        }
        System.arraycopy(buf, 0, output, outOffset, buf.length);
    }

    public final byte[] doFinal(byte[] input) throws IllegalStateException {
        update(input);
        return doFinal();
    }

    public final void reset() {
        macSpi_.engineReset();
    }

    public final Object clone() throws CloneNotSupportedException {
        return new Mac((MacSpi) macSpi_.clone(), provider_, algorithm_);
    }
}
