/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */
package de.flexiprovider.core.kdf;

import de.flexiprovider.api.KeyDerivation;
import de.flexiprovider.api.MessageDigest;
import de.flexiprovider.api.exceptions.DigestException;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.util.ByteUtils;
import de.flexiprovider.core.md.SHA1;

/**
 * X963 is a key derivation function defined in ANSI X9.63.
 * <p>
 * X963 can be used as follows:
 * 
 * <pre>
 * KeyDerivation kdf = Registry.getKeyDerivation(&quot;X963&quot;);
 * kdf.init(secretKey.toByteArray());
 * kdf.setSharedInfo(byte[] sharedInfo);
 * byte[] derivedKey = kdf.doFinal(int keyDataLen);
 * </pre>
 * 
 * @author Jochen Hechler
 * @author Marcus Stögbauer
 * @author Martin Döring
 */
public class X963 extends KeyDerivation {

    // the hash function
    private MessageDigest md;

    // the secret key
    private byte[] z;

    // a shared info string
    private byte[] sharedInfo;

    /**
     * Constructor. Set the message digest.
     */
    public X963() {
	md = new SHA1();
    }

    /**
     * Initialize the KDF with a secret and parameters. The parameters have to
     * be <tt>null</tt> or an instance of {@link KDFParameterSpec}.
     * 
     * @param secret
     *                the secret from which to derive the key
     * @param params
     *                the parameters
     * @throws InvalidKeyException
     *                 if the secret is <tt>null</tt>.
     * @throws InvalidAlgorithmParameterException
     *                 if the parameters are not <tt>null</tt> and not an
     *                 instance of {@link KDFParameterSpec}.
     */
    public void init(byte[] secret, AlgorithmParameterSpec params)
	    throws InvalidKeyException, InvalidAlgorithmParameterException {
	if (secret == null) {
	    throw new InvalidKeyException("null");
	}
	z = ByteUtils.clone(secret);

	if (params != null) {
	    if (!(params instanceof KDFParameterSpec)) {
		throw new InvalidAlgorithmParameterException("unsupported type");
	    }
	    sharedInfo = ((KDFParameterSpec) params).getSharedInfo();
	}
    }

    /**
     * This function does the actual key derivation. It uses the shared key
     * value Z from above and the given key size with the desired hash function
     * H and the optional <tt>SharedInfo</tt> and computes
     * 
     * <pre>
     * Hash&lt;sup&gt;i&lt;/sup&gt; = H(Z || counter || [SharedInfo])
     * </pre>
     * 
     * where the counter is a 32 bit string.
     * 
     * @param keySize
     *                the desired length of the derived key
     * @return the derived key with the specified length, or <tt>null</tt> if
     *         the key size is <tt>&lt; 0</tt>.
     */
    public byte[] deriveKey(int keySize) {

	if (keySize < 0) {
	    return null;
	}

	int mdLength = md.getDigestLength();
	int d = keySize / mdLength;
	int t = keySize % mdLength;

	byte[] result = new byte[keySize];
	byte[] counter = new byte[4];
	try {
	    for (int i = 0; i < d; i++) {
		counter = increase(counter);
		md.update(z);
		md.update(counter);
		md.update(sharedInfo);
		md.digest(result, i * mdLength, mdLength);
	    }
	} catch (DigestException e) {
	    // must not happen
	    throw new RuntimeException("internal error");
	}

	if (t != 0) {
	    // derive remaining key bytes
	    counter = increase(counter);
	    md.update(z);
	    md.update(counter);
	    md.update(sharedInfo);
	    byte[] last = md.digest();
	    System.arraycopy(last, 0, result, d * mdLength, t);
	}

	// return the derived key
	return result;
    }

    /**
     * This little 'gem' is a an exponential function to increase a value in a
     * byte array by 1.
     * 
     * @param b
     *                the byte array holding the value
     * @return the increased value
     */
    private byte[] increase(byte[] b) {
	int[] i = new int[4];
	i[0] = (256 + b[0]) % 256;
	i[1] = (256 + b[1]) % 256;
	i[2] = (256 + b[2]) % 256;
	i[3] = (256 + b[3]) % 256;
	if ((++(i[0])) == 256) {
	    if ((++(i[1])) == 256) {
		if ((++(i[2])) == 256) {
		    i[3]++;
		}
	    }
	}
	b[0] = (byte) i[0];
	b[1] = (byte) i[1];
	b[2] = (byte) i[2];
	b[3] = (byte) i[3];
	return b;
    }

}
