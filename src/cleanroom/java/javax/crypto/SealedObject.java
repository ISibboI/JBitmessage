/* Copyright 2000 Fraunhofer Gesellschaft
 * Leonrodstr. 54, 80636 Munich, Germany.
 * All rights reserved.
 *
 * You shall use this software only in accordance with
 * the terms of the license agreement you entered into
 * with Fraunhofer Gesellschaft.
 */
package javax.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * @author Patric Kabus
 * @author Volker Roth
 * @version "$Id: SealedObject.java,v 1.1.1.1 2001/05/15 11:59:09 krprvadm Exp $"
 */
public class SealedObject extends Object implements Serializable {
    private byte[] params_;

    private String pAlg_;

    private String algorithm_;

    private byte[] data_;

    public SealedObject(Serializable object, Cipher cipher) throws IOException,
            IllegalBlockSizeException {
        ByteArrayOutputStream byteOut;
        AlgorithmParameters params;
        ObjectOutputStream objectOut;

        if (cipher == null) {
            throw new NullPointerException("cipher");
        }
        byteOut = new ByteArrayOutputStream();
        objectOut = new ObjectOutputStream(byteOut);

        objectOut.writeObject(object);
        objectOut.flush();

        try {
            data_ = cipher.doFinal(byteOut.toByteArray());
        } catch (BadPaddingException e) {
            throw new IllegalStateException(e.toString());
        }
        objectOut.close();

        params = cipher.getParameters();

        if (params != null) {
            params_ = params.getEncoded();
            pAlg_ = params.getAlgorithm();
        }
        algorithm_ = cipher.getAlgorithm();
    }

    public final String getAlgorithm() {
        return algorithm_;
    }

    public final Object getObject(Key key) throws IOException,
            ClassNotFoundException, NoSuchAlgorithmException,
            InvalidKeyException {
        AlgorithmParameters params;
        Cipher cipher;

        if (key == null) {
            throw new NullPointerException("key");
        }
        try {
            cipher = Cipher.getInstance(algorithm_);

            if (params_ != null) {
                params = AlgorithmParameters.getInstance(pAlg_);
                params.init(params_);

                cipher.init(Cipher.DECRYPT_MODE, key, params);
            } else {
                cipher.init(Cipher.DECRYPT_MODE, key);
            }
            return getObject(cipher);
        } catch (BadPaddingException e) {
            throw new IllegalStateException(e.getMessage());
        } catch (NoSuchPaddingException e) {
            throw new IllegalStateException(e.getMessage());
        } catch (InvalidAlgorithmParameterException e) {
            throw new IllegalStateException(e.getMessage());
        } catch (IllegalBlockSizeException e) {
            throw new IllegalStateException(e.getMessage());
        }
    }

    public final Object getObject(Cipher cipher) throws IOException,
            ClassNotFoundException, IllegalBlockSizeException,
            BadPaddingException {
        ByteArrayInputStream byteIn;
        ObjectInputStream objectIn;
        byte[] buf;

        if (cipher == null) {
            throw new NullPointerException("cipher");
        }
        buf = cipher.doFinal(data_);
        byteIn = new ByteArrayInputStream(buf);
        objectIn = new ObjectInputStream(byteIn);

        try {
            return objectIn.readObject();
        } finally {
            objectIn.close();
        }
    }

    public final Object getObject(Key key, String provider) throws IOException,
            ClassNotFoundException, NoSuchAlgorithmException,
            NoSuchProviderException, InvalidKeyException {
        AlgorithmParameters params;
        Cipher cipher;

        if (key == null) {
            throw new NullPointerException("key");
        }
        if (provider == null) {
            throw new NullPointerException("provider");
        }
        try {
            cipher = Cipher.getInstance(algorithm_, provider);

            if (params_ != null) {
                params = AlgorithmParameters.getInstance(pAlg_);
                params.init(params_);

                cipher.init(Cipher.DECRYPT_MODE, key, params);
            } else {
                cipher.init(Cipher.DECRYPT_MODE, key);
            }
            return getObject(cipher);
        } catch (BadPaddingException e) {
            throw new IllegalStateException(e.toString());
        } catch (NoSuchPaddingException e) {
            throw new IllegalStateException(e.toString());
        } catch (InvalidAlgorithmParameterException e) {
            throw new IllegalStateException(e.toString());
        } catch (IllegalBlockSizeException e) {
            throw new IllegalStateException(e.toString());
        }
    }
}
