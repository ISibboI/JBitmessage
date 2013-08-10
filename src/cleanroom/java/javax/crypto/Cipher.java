/* Copyright 2000 Fraunhofer Gesellschaft
 * Leonrodstr. 54, 80636 Munich, Germany.
 * All rights reserved.
 *
 * You shall use this software only in accordance with
 * the terms of the license agreement you entered into
 * with Fraunhofer Gesellschaft.
 */
package javax.crypto;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.StringTokenizer;

/**
 * This class provides the functionality of a cryptographic cipher for
 * encryption and decryption. It forms the core of the Java Cryptographic
 * Extension (JCE) framework.
 * 
 * <p>
 * In order to create a Cipher object, the application calls the Cipher's
 * <tt>getInstance</tt> method, and passes the name of the requested
 * <i>transformation</i> to it. Optionally, the name of a provider may be
 * specified.
 * 
 * <p>
 * A <i>transformation</i> is a string that describes the operation (or set of
 * operations) to be performed on the given input, to produce some output. A
 * transformation always includes the name of a cryptographic algorithm (e.g.,
 * <i>DES</i>), and may be followed by a feedback mode and padding scheme.
 * 
 * <p>
 * A transformation is of the form:
 * <p>
 * 
 * <ul>
 * <li>"<i>algorithm/mode/padding</i>" or
 * <p>
 * <li>"<i>algorithm</i>"
 * </ul>
 * 
 * <P>
 * (in the latter case, provider-specific default values for the mode and
 * padding scheme are used). For example, the following is a valid
 * transformation:
 * <p>
 * 
 * <pre>
 * Cipher c = Cipher.getInstance(&quot;&lt;i&gt;DES/CBC/PKCS5Padding&lt;/i&gt;&quot;);
 * </pre>
 * 
 * <p>
 * When requesting a block cipher in stream cipher mode (e.g., <tt>DES</tt> in
 * <tt>CFB</tt> or <tt>OFB</tt> mode), the user may optionally specify the
 * number of bits to be processed at a time, by appending this number to the
 * mode name as shown in the "<i>DES/CFB8/NoPadding</i>" and "<i>DES/OFB32/PKCS5Padding</i>"
 * transformations. If no such number is specified, a provider-specific default
 * is used. (For example, the "SunJCE" provider uses a default of 64 bits.)
 * 
 * <p>
 * See Also: <tt>KeyGenerator</tt>, <tt>SecretKey</tt>
 * 
 * @author Patric Kabus
 * @version $Id: Cipher.java,v 1.2 2001/10/04 14:58:03 weinmann Exp $
 */
public class Cipher extends Object {
    public static final int ENCRYPT_MODE = 1;

    public static final int DECRYPT_MODE = 2;

    public static final int WRAP_MODE = 3;

    public static final int UNWRAP_MODE = 4;

    /**
     * The cipher implementation used by this instance.
     */
    private CipherSpi cipherSpi_;

    /**
     * The provider used by this instance.
     */
    private Provider provider_;

    /**
     * States wether this cipher has been initialised.
     */
    private boolean init_;

    /**
     * The transformation used by this instance.
     */
    private String transformation_;

    /**
     * Creates a Cipher object.
     * 
     * @param cipherSpi
     *                The delegate.
     * @param provider
     *                The provider.
     * @param transformation
     *                The transformation.
     */
    protected Cipher(CipherSpi cipherSpi, Provider provider,
	    String transformation) {
	if (cipherSpi == null) {
	    throw new NullPointerException("cipherSpi");
	}
	if (provider == null) {
	    throw new NullPointerException("provider");
	}
	if (transformation == null) {
	    throw new NullPointerException("transformation");
	}
	init_ = false;
	cipherSpi_ = cipherSpi;
	provider_ = provider;
	transformation_ = transformation;
    }

    /**
     * Generates a <tt>Cipher</tt> object that implements the specified
     * transformation.
     * 
     * <p>
     * If the default provider package supplies an implementation of the
     * requested transformation, an instance of <tt>Cipher</tt> containing
     * that implementation is returned. If the transformation is not available
     * in the default provider package, other provider packages are searched.
     * 
     * @param transformation
     *                The name of the transformation, e.g.,
     *                <i>DES/CBC/PKCS5Padding</i>. See Appendix A in the <a
     *                href="../../../guide/API_users_guide.html#AppA"> Java
     *                Cryptography Extension API Specification &amp; Reference
     *                </a> for information about standard transformation names.
     * @return A cipher that implements the requested transformation
     * @throws NoSuchAlgorithmException
     *                 if the specified transformation is not available in the
     *                 default provider package or any of the other provider
     *                 packages that were searched.
     * @throws NoSuchPaddingException
     *                 if <tt>transformation</tt> contains a padding scheme
     *                 that is not available.
     */
    public static final Cipher getInstance(String transformation)
	    throws NoSuchAlgorithmException, NoSuchPaddingException {
	CipherSpi cs;
	Object[] o;

	if (transformation == null) {
	    throw new NullPointerException("transformation");
	}
	o = Util.getImpl(transformation, Util.CIPHER);
	cs = initCipherSpi((CipherSpi) o[0], transformation);

	return new Cipher(cs, (Provider) o[1], transformation);
    }

    /**
     * Creates a <tt>Cipher</tt> object that implements the specified
     * transformation, as supplied by the specified provider.
     * 
     * @param transformation
     *                The name of the transformation, e.g.,
     *                <i>DES/CBC/PKCS5Padding</i>. See Appendix A in the <a
     *                href="../../../guide/API_users_guide.html#AppA"> Java
     *                Cryptography Extension API Specification &amp; Reference
     *                </a> for information about standard transformation names.
     * @param provider
     *                The name of the provider.
     * @return A cipher that implements the requested transformation
     * @throws NoSuchAlgorithmException
     *                 if no transformation was specified, or if the specified
     *                 transformation is not available from the specified
     *                 provider.
     * @throws NoSuchProviderException
     *                 if the specified provider has not been configured.
     * @throws NoSuchPaddingException
     *                 if <tt>transformation</tt> contains a padding scheme
     *                 that is not available.
     */
    public static final Cipher getInstance(String transformation,
	    String provider) throws NoSuchAlgorithmException,
	    NoSuchProviderException, NoSuchPaddingException {
	CipherSpi cs;
	Object[] o;

	if (transformation == null) {
	    throw new NullPointerException("transformation");
	}
	if (provider == null) {
	    throw new NullPointerException("provider");
	}
	o = Util.getImpl(transformation, Util.CIPHER, provider);
	cs = initCipherSpi((CipherSpi) o[0], transformation);

	return new Cipher(cs, (Provider) o[1], transformation);
    }

    private static CipherSpi initCipherSpi(CipherSpi cs, String transformation)
	    throws NoSuchAlgorithmException, NoSuchPaddingException {
	StringTokenizer st;
	String tmp;
	int i;

	i = 0;
	st = new StringTokenizer(transformation, "/");

	if (st.hasMoreTokens()) {
	    st.nextToken();
	    i++;
	}
	if (st.hasMoreTokens()) {
	    // System.out.println(st.nextToken());
	    tmp = st.nextToken();

	    if (tmp.length() > 0) {
		cs.engineSetMode(tmp);
	    }
	    i++;
	}
	if (st.hasMoreTokens()) {
	    // System.out.println(st.nextToken());
	    tmp = st.nextToken();

	    if (tmp.length() > 0) {
		cs.engineSetPadding(tmp);
	    }
	    i++;
	}
	if (i == 0 || i == 2 || st.hasMoreTokens()) {
	    throw new NoSuchAlgorithmException("Wrong transformation format");
	}
	return cs;
    }

    /**
     * Returns the provider of this <tt>Cipher</tt> object.
     * 
     * @return The provider of this <tt>Cipher</tt> object.
     */
    public final Provider getProvider() {
	return provider_;
    }

    /**
     * Returns the algorithm name of this <tt>Cipher</tt> object.
     * 
     * <p>
     * This is the same name that was specified in one of the
     * <tt>getInstance</tt> calls that created this <tt>Cipher</tt> object.
     * 
     * @return the algorithm name of this <tt>Cipher</tt> object.
     */
    public final String getAlgorithm() {
	return transformation_;
    }

    /**
     * Returns the block size (in bytes).
     * 
     * @return The block size (in bytes), or 0 if the underlying algorithm is
     *         not a block cipher.
     */
    public final int getBlockSize() {
	return cipherSpi_.engineGetBlockSize();
    }

    /**
     * Returns the length in bytes that an output buffer would need to be in
     * order to hold the result of the next <tt>update</tt> or
     * <tt>doFinal</tt> operation, given the input length <tt>inputLen</tt>
     * (in bytes).
     * 
     * <p>
     * This call takes into account any unprocessed (buffered) data from a
     * previous <tt>update</tt> call, and padding.
     * 
     * <p>
     * The actual output length of the next <tt>update</tt> or
     * <tt>doFinal</tt> call may be smaller than the length returned by this
     * method.
     * 
     * @param inputLen
     *                The input length (in bytes)
     * @return The required output buffer size (in bytes)
     * @throws IllegalStateException
     *                 if this cipher is in a wrong state (e.g., has not yet
     *                 been initialized)
     */
    public final int getOutputSize(int inputLen) throws IllegalStateException {
	if (!init_) {
	    throw new IllegalStateException("not initialised");
	}
	return cipherSpi_.engineGetOutputSize(inputLen);
    }

    /**
     * Returns the initialization vector (IV) in a new buffer.
     * 
     * <p>
     * This is useful in the case where a random IV was created, or in the
     * context of password-based encryption or decryption, where the IV is
     * derived from a user-supplied password.
     * 
     * @return The initialization vector in a new buffer, or null if the
     *         underlying algorithm does not use an IV, or if the IV has not yet
     *         been set.
     */
    public final byte[] getIV() {
	return cipherSpi_.engineGetIV();
    }

    /**
     * Returns the parameters used with this cipher.
     * 
     * <p>
     * The returned parameters may be the same that were used to initialize this
     * cipher, or may contain a combination of default and random parameter
     * values used by the underlying cipher implementation if this cipher
     * requires algorithm parameters but was not initialized with any.
     * 
     * @return The parameters used with this cipher, or null if this cipher does
     *         not use any parameters.
     */
    public final AlgorithmParameters getParameters() {
	return cipherSpi_.engineGetParameters();
    }

    /**
     * Initializes this cipher with a key.
     * 
     * <p>
     * The cipher is initialized for encryption or decryption, depending on the
     * value of <tt>opmode</tt>.
     * 
     * <p>
     * If this cipher requires any algorithm parameters that cannot be derived
     * from the given <tt>key</tt>, the underlying cipher implementation is
     * supposed to generate the required parameters itself (using
     * provider-specific default or random values) if it is being initialized
     * for encryption, and raise an <tt>InvalidKeyException</tt> if it is
     * being initialized for decryption. The generated parameters can be
     * retrieved using <tt>getParameters()</tt> or <tt>getIV()</tt> (if the
     * parameter is an IV).
     * 
     * <p>
     * If this cipher (including its underlying feedback or padding scheme)
     * requires any random bytes (e.g., for parameter generation), it will get
     * them using the <tt>java.security.SecureRandom</tt> implementation of
     * the highest-priority installed provider as the source of randomness. (If
     * none of the installed providers supply an implementation of SecureRandom,
     * a system-provided source of randomness will be used.)
     * 
     * <p>
     * Note that when a Cipher object is initialized, it loses all
     * previously-acquired state. In other words, initializing a Cipher is
     * equivalent to creating a new instance of that Cipher and initializing it.
     * 
     * @param opmode
     *                The operation mode of this cipher (this is either
     *                <tt>ENCRYPT_MODE</tt> or <tt>DECRYPT_MODE</tt>).
     * @param key
     *                The key.
     * @throws InvalidKeyException
     *                 if the given key is inappropriate for initializing this
     *                 cipher, or if this cipher is being initialized for
     *                 decryption and requires algorithm parameters that cannot
     *                 be determined from the given key.
     */
    public final void init(int opmode, Key key) throws InvalidKeyException {
	init(opmode, key, new SecureRandom());
    }

    /**
     * Initializes this cipher with a key and a source of randomness.
     * 
     * <p>
     * The cipher is initialized for encryption or decryption, depending on the
     * value of <tt>opmode</tt>.
     * 
     * <p>
     * If this cipher requires any algorithm parameters that cannot be derived
     * from the given <tt>key</tt>, the underlying cipher implementation is
     * supposed to generate the required parameters itself (using
     * provider-specific default or random values) if it is being initialized
     * for encryption, and raise an <tt>InvalidKeyException</tt> if it is
     * being initialized for decryption. The generated parameters can be
     * retrieved using <tt>engineGetParameters()</tt> or
     * <tt>engineGetIV()</tt> (if the parameter is an IV).
     * 
     * <p>
     * If this cipher (including its underlying feedback or padding scheme)
     * requires any random bytes (e.g., for parameter generation), it will get
     * them from <tt>random</tt>.
     * 
     * <p>
     * Note that when a Cipher object is initialized, it loses all
     * previously-acquired state. In other words, initializing a Cipher is
     * equivalent to creating a new instance of that Cipher and initializing it.
     * 
     * @param opmode
     *                The operation mode of this cipher (this is either
     *                <tt>ENCRYPT_MODE</tt> or <tt>DECRYPT_MODE</tt>).
     * @param key
     *                The key.
     * @param random
     *                The source of randomness.
     * @throws InvalidKeyException -
     *                 if the given key is inappropriate for initializing this
     *                 cipher, or if this cipher is being initialized for
     *                 decryption and requires algorithm parameters that cannot
     *                 be determined from the given key.
     */
    public final void init(int opmode, Key key, SecureRandom random)
	    throws InvalidKeyException {
	if (opmode != ENCRYPT_MODE && opmode != DECRYPT_MODE) {
	    throw new IllegalArgumentException("Illegal opmode (" + opmode
		    + ")");
	}
	if (key == null) {
	    throw new NullPointerException("key");
	}
	if (random == null) {
	    throw new NullPointerException("random");
	}
	cipherSpi_.engineInit(opmode, key, random);

	init_ = true;
    }

    /**
     * Initializes this cipher with a key and a set of algorithm parameters.
     * 
     * <p>
     * The cipher is initialized for encryption or decryption, depending on the
     * value of <tt>opmode</tt>.
     * 
     * <p>
     * If this cipher requires any algorithm parameters and <tt>params</tt> is
     * null, the underlying cipher implementation is supposed to generate the
     * required parameters itself (using provider-specific default or random
     * values) if it is being initialized for encryption, and raise an
     * <tt>InvalidAlgorithmParameterException</tt> if it is being initialized
     * for decryption. The generated parameters can be retrieved using
     * <tt>engineGetParameters()</tt> or <tt>engineGetIV()</tt> (if the
     * parameter is an IV).
     * 
     * <p>
     * If this cipher (including its underlying feedback or padding scheme)
     * requires any random bytes (e.g., for parameter generation), it will get
     * them using the <tt>java.security.SecureRandom</tt> implementation of
     * the highest-priority installed provider as the source of randomness. (If
     * none of the installed providers supply an implementation of SecureRandom,
     * a system-provided source of randomness will be used.)
     * 
     * <p>
     * Note that when a Cipher object is initialized, it loses all
     * previously-acquired state. In other words, initializing a Cipher is
     * equivalent to creating a new instance of that Cipher and initializing it.
     * 
     * @param opmode
     *                The operation mode of this cipher (this is either
     *                <tt>ENCRYPT_MODE</tt> or <tt>DECRYPT_MODE</tt>).
     * @param key
     *                The encryption key.
     * @param params
     *                The algorithm parameters
     * @throws InvalidKeyException
     *                 if the given key is inappropriate for initializing this
     *                 cipher
     * @throws InvalidAlgorithmParameterException
     *                 if the given algorithm parameters are inappropriate for
     *                 this cipher, or if this cipher is being initialized for
     *                 decryption and requires algorithm parameters and
     *                 <tt>params</tt> is null.
     */
    public final void init(int opmode, Key key, AlgorithmParameterSpec params)
	    throws InvalidKeyException, InvalidAlgorithmParameterException {
	init(opmode, key, params, new SecureRandom());
    }

    /**
     * Initializes this cipher with a key, a set of algorithm parameters, and a
     * source of randomness.
     * 
     * <p>
     * The cipher is initialized for encryption or decryption, depending on the
     * value of <tt>opmode</tt>.
     * 
     * <p>
     * If this cipher requires any algorithm parameters and <tt>params</tt> is
     * null, the underlying cipher implementation is supposed to generate the
     * required parameters itself (using provider-specific default or random
     * values) if it is being initialized for encryption, and raise an
     * <tt>InvalidAlgorithmParameterException</tt> if it is being initialized
     * for decryption. The generated parameters can be retrieved using
     * <tt>engineGetParameters()</tt> or <tt>engineGetIV()</tt> (if the
     * parameter is an IV).
     * 
     * <p>
     * If this cipher (including its underlying feedback or padding scheme)
     * requires any random bytes (e.g., for parameter generation), it will get
     * them from <tt>random</tt>.
     * 
     * <p>
     * Note that when a Cipher object is initialized, it loses all
     * previously-acquired state. In other words, initializing a Cipher is
     * equivalent to creating a new instance of that Cipher and initializing it.
     * 
     * @param opmode
     *                The operation mode of this cipher (this is either
     *                <tt>ENCRYPT_MODE</tt> or <tt>DECRYPT_MODE</tt>).
     * @param key
     *                The encryption key.
     * @param params
     *                The algorithm parameters.
     * @param random
     *                The source of randomness.
     * @throws InvalidKeyException
     *                 if the given key is inappropriate for initializing this
     *                 cipher.
     * @throws InvalidAlgorithmParameterException
     *                 if the given algorithm parameters are inappropriate for
     *                 this cipher, or if this cipher is being initialized for
     *                 decryption and requires algorithm parameters and
     *                 <tt>params</tt> is null.
     */
    public final void init(int opmode, Key key, AlgorithmParameterSpec params,
	    SecureRandom random) throws InvalidKeyException,
	    InvalidAlgorithmParameterException {
	if (opmode != ENCRYPT_MODE && opmode != DECRYPT_MODE) {
	    throw new IllegalArgumentException("Illegal opmode (" + opmode
		    + ")");
	}
	if (key == null) {
	    throw new NullPointerException("key");
	}
	if (random == null) {
	    throw new NullPointerException("random");
	}
	cipherSpi_.engineInit(opmode, key, params, random);

	init_ = true;
    }

    /**
     * Initializes this cipher with a key and a set of algorithm parameters.
     * 
     * <p>
     * The cipher is initialized for encryption or decryption, depending on the
     * value of <tt>opmode</tt>.
     * 
     * <p>
     * If this cipher requires any algorithm parameters and <tt>params</tt> is
     * null, the underlying cipher implementation is supposed to generate the
     * required parameters itself (using provider-specific default or random
     * values) if it is being initialized for encryption, and raise an
     * <tt>InvalidAlgorithmParameterException</tt> if it is being initialized
     * for decryption. The generated parameters can be retrieved using
     * <tt>engineGetParameters()</tt> or <tt>engineGetIV()</tt> (if the
     * parameter is an IV).
     * 
     * <p>
     * If this cipher (including its underlying feedback or padding scheme)
     * requires any random bytes (e.g., for parameter generation), it will get
     * them using the <tt>java.security.SecureRandom</tt> implementation of
     * the highest-priority installed provider as the source of randomness. (If
     * none of the installed providers supply an implementation of SecureRandom,
     * a system-provided source of randomness will be used.)
     * 
     * <p>
     * Note that when a Cipher object is initialized, it loses all
     * previously-acquired state. In other words, initializing a Cipher is
     * equivalent to creating a new instance of that Cipher and initializing it.
     * 
     * @param opmode
     *                The operation mode of this cipher (this is either
     *                <tt>ENCRYPT_MODE</tt> or <tt>DECRYPT_MODE</tt>).
     * @param key
     *                The encryption key.
     * @param params
     *                The algorithm parameters.
     * @throws InvalidKeyException
     *                 if the given key is inappropriate for initializing this
     *                 cipher.
     * @throws InvalidAlgorithmParameterException
     *                 if the given algorithm parameters are inappropriate for
     *                 this cipher, or if this cipher is being initialized for
     *                 decryption and requires algorithm parameters and
     *                 <tt>params</tt> is null.
     */
    public final void init(int opmode, Key key, AlgorithmParameters params)
	    throws InvalidKeyException, InvalidAlgorithmParameterException {
	init(opmode, key, params, new SecureRandom());
    }

    /**
     * Initializes this cipher with a key, a set of algorithm parameters, and a
     * source of randomness.
     * 
     * <p>
     * The cipher is initialized for encryption or decryption, depending on the
     * value of <tt>opmode</tt>.
     * 
     * <p>
     * If this cipher requires any algorithm parameters and <tt>params</tt> is
     * null, the underlying cipher implementation is supposed to generate the
     * required parameters itself (using provider-specific default or random
     * values) if it is being initialized for encryption, and raise an
     * <tt>InvalidAlgorithmParameterException</tt> if it is being initialized
     * for decryption. The generated parameters can be retrieved using
     * <tt>engineGetParameters()</tt> or <tt>engineGetIV()</tt> (if the
     * parameter is an IV).
     * 
     * <p>
     * If this cipher (including its underlying feedback or padding scheme)
     * requires any random bytes (e.g., for parameter generation), it will get
     * them from <tt>random</tt>.
     * 
     * <p>
     * Note that when a Cipher object is initialized, it loses all
     * previously-acquired state. In other words, initializing a Cipher is
     * equivalent to creating a new instance of that Cipher and initializing it.
     * 
     * @param opmode
     *                The operation mode of this cipher (this is either
     *                <tt>ENCRYPT_MODE</tt> or <tt>DECRYPT_MODE</tt>).
     * @param key
     *                The encryption key.
     * @param params
     *                The algorithm parameters.
     * @param random
     *                The source of randomness.
     * @throws InvalidKeyException
     *                 if the given key is inappropriate for initializing this
     *                 cipher.
     * @throws InvalidAlgorithmParameterException
     *                 if the given algorithm parameters are inappropriate for
     *                 this cipher, or if this cipher is being initialized for
     *                 decryption and requires algorithm parameters and
     *                 <tt>params</tt> is null.
     */
    public final void init(int opmode, Key key, AlgorithmParameters params,
	    SecureRandom random) throws InvalidKeyException,
	    InvalidAlgorithmParameterException {
	if (opmode != ENCRYPT_MODE && opmode != DECRYPT_MODE) {
	    throw new IllegalArgumentException("Illegal opmode (" + opmode
		    + ")");
	}
	if (key == null) {
	    throw new NullPointerException("key");
	}
	if (params == null) {
	    throw new NullPointerException("params");
	}
	if (random == null) {
	    throw new NullPointerException("random");
	}
	cipherSpi_.engineInit(opmode, key, params, random);

	init_ = true;
    }

    /**
     * Continues a multiple-part encryption or decryption operation (depending
     * on how this cipher was initialized), processing another data part.
     * 
     * <p>
     * The bytes in the <tt>input</tt> buffer are processed, and the result is
     * stored in a new buffer.
     * 
     * <p>
     * If <tt>input</tt> has a length of zero, this method returns
     * <tt>null</tt>.
     * 
     * @param input
     *                The input buffer.
     * @return the new buffer with the result, or null if the underlying cipher
     *         is a block cipher and the input data is too short to result in a
     *         new block.
     * @throws IllegalStateException -
     *                 if this cipher is in a wrong state (e.g., has not been
     *                 initialized).
     */
    public final byte[] update(byte[] input) throws IllegalStateException {
	if (input == null) {
	    throw new NullPointerException("input");
	}
	return update(input, 0, input.length);
    }

    /**
     * Continues a multiple-part encryption or decryption operation (depending
     * on how this cipher was initialized), processing another data part.
     * 
     * <p>
     * The first <tt>inputLen</tt> bytes in the <tt>input</tt> buffer,
     * starting at <tt>inputOffset</tt> inclusive, are processed, and the
     * result is stored in a new buffer.
     * 
     * <p>
     * If <tt>inputLen</tt> is zero, this method returns <tt>null</tt>.
     * 
     * @param input
     *                The input buffer.
     * @param inputOffset
     *                The offset in <tt>input</tt> where the input starts.
     * @param inputLen
     *                The input length.
     * @return The new buffer with the result, or null if the underlying cipher
     *         is a block cipher and the input data is too short to result in a
     *         new block.
     * @throws IllegalStateException
     *                 if this cipher is in a wrong state (e.g., has not been
     *                 initialized)
     */
    public final byte[] update(byte[] input, int inputOffset, int inputLen)
	    throws IllegalStateException {
	if (!init_) {
	    throw new IllegalStateException("not initialised");
	}
	checkInputParameters(input, inputOffset, inputLen);

	return cipherSpi_.engineUpdate(input, inputOffset, inputLen);
    }

    /**
     * Continues a multiple-part encryption or decryption operation (depending
     * on how this cipher was initialized), processing another data part.
     * 
     * <p>
     * The first <tt>inputLen</tt> bytes in the <tt>input</tt> buffer,
     * starting at <tt>inputOffset</tt> inclusive, are processed, and the
     * result is stored in the <tt>output</tt> buffer.
     * 
     * <p>
     * If the <tt>output</tt> buffer is too small to hold the result, a
     * <tt>ShortBufferException</tt> is thrown. In this case, repeat this call
     * with a larger output buffer. Use <tt>getOutputSize()</tt> to determine
     * how big the output buffer should be.
     * 
     * <p>
     * If <tt>inputLen</tt> is zero, this method returns a length of zero.
     * 
     * @param input
     *                The input buffer.
     * @param inputOffset
     *                The offset in <tt>input</tt> where the input starts.
     * @param inputLen
     *                The input length.
     * @param output
     *                the buffer for the result.
     * @return The number of bytes stored in <tt>output</tt>.
     * @throws IllegalStateException
     *                 if this cipher is in a wrong state (e.g., has not been
     *                 initialized).
     * @throws ShortBufferException
     *                 if the given output buffer is too small to hold the
     *                 result.
     */
    public final int update(byte[] input, int inputOffset, int inputLen,
	    byte[] output) throws IllegalStateException, ShortBufferException {
	return update(input, inputOffset, inputLen, output, 0);
    }

    /**
     * Continues a multiple-part encryption or decryption operation (depending
     * on how this cipher was initialized), processing another data part.
     * 
     * <p>
     * The first <tt>inputLen</tt> bytes in the <tt>input</tt> buffer,
     * starting at <tt>inputOffset</tt> inclusive, are processed, and the
     * result is stored in the <tt>output</tt> buffer, starting at
     * <tt>outputOffset</tt> inclusive.
     * 
     * <p>
     * If the <tt>output</tt> buffer is too small to hold the result, a
     * <tt>ShortBufferException</tt> is thrown. In this case, repeat this call
     * with a larger output buffer. Use <tt>getOutputSize()</tt> to determine
     * how big the output buffer should be.
     * 
     * <p>
     * If <tt>inputLen</tt> is zero, this method returns a length of zero.
     * 
     * @param input
     *                The input buffer.
     * @param inputOffset
     *                The offset in <tt>input</tt> where the input starts.
     * @param inputLen
     *                The input length.
     * @param output
     *                The buffer for the result.
     * @param outputOffset
     *                The offset in <tt>output</tt> where the result is
     *                stored.
     * @return The number of bytes stored in <tt>output</tt>.
     * @throws IllegalStateException
     *                 if this cipher is in a wrong state (e.g., has not been
     *                 initialized).
     * @throws ShortBufferException
     *                 if the given output buffer is too small to hold the
     *                 result.
     */
    public final int update(byte[] input, int inputOffset, int inputLen,
	    byte[] output, int outputOffset) throws IllegalStateException,
	    ShortBufferException {
	if (!init_) {
	    throw new IllegalStateException("not initialised");
	}
	checkInputParameters(input, inputOffset, inputLen);
	checkOutputParameters(output, outputOffset);

	return cipherSpi_.engineUpdate(input, inputOffset, inputLen, output,
		outputOffset);
    }

    /**
     * Finishes a multiple-part encryption or decryption operation, depending on
     * how this cipher was initialized.
     * 
     * <p>
     * Input data that may have been buffered during a previous <tt>update</tt>
     * operation is processed, with padding (if requested) being applied. The
     * result is stored in a new buffer.
     * 
     * <p>
     * A call to this method resets this cipher object to the state it was in
     * when previously initialized via a call to <tt>init</tt>. That is, the
     * object is reset and available to encrypt or decrypt (depending on the
     * operation mode that was specified in the call to <tt>init</tt>) more
     * data.
     * 
     * @return The new buffer with the result.
     * @throws IllegalStateException
     *                 if this cipher is in a wrong state (e.g., has not been
     *                 initialized).
     * @throws IllegalBlockSizeException
     *                 if this cipher is a block cipher, no padding has been
     *                 requested (only in encryption mode), and the total input
     *                 length of the data processed by this cipher is not a
     *                 multiple of block size.
     * @throws BadPaddingException
     *                 if this cipher is in decryption mode, and (un)padding has
     *                 been requested, but the decrypted data is not bounded by
     *                 the appropriate padding bytes
     */
    public final byte[] doFinal() throws IllegalStateException,
	    IllegalBlockSizeException, BadPaddingException {
	if (!init_) {
	    throw new IllegalStateException("not initialised");
	}
	return cipherSpi_.engineDoFinal(null, 0, 0);
    }

    /**
     * Finishes a multiple-part encryption or decryption operation, depending on
     * how this cipher was initialized.
     * 
     * <p>
     * Input data that may have been buffered during a previous <tt>update</tt>
     * operation is processed, with padding (if requested) being applied. The
     * result is stored in a new buffer.
     * 
     * <p>
     * If the <tt>output</tt> buffer is too small to hold the result, a
     * <tt>ShortBufferException</tt> is thrown. In this case, repeat this call
     * with a larger output buffer. Use <tt>getOutputSize()</tt> to determine
     * how big the output buffer should be.
     * 
     * <p>
     * A call to this method resets this cipher object to the state it was in
     * when previously initialized via a call to <tt>init</tt>. That is, the
     * object is reset and available to encrypt or decrypt (depending on the
     * operation mode that was specified in the call to <tt>init</tt>) more
     * data.
     * 
     * @param output
     *                the buffer for the result.
     * @param outputOffset
     *                the offset in <tt>output</tt> where the result is
     *                stored.
     * @return The new buffer with the result.
     * @throws IllegalStateException
     *                 if this cipher is in a wrong state (e.g. has not been
     *                 initialized).
     * @throws IllegalBlockSizeException
     *                 if this cipher is a block cipher, no padding has been
     *                 requested (only in encryption mode), and the total input
     *                 length of the data processed by this cipher is not a
     *                 multiple of block size.
     * @throws ShortBufferException
     *                 if the given output buffer is too small to hold the
     *                 result.
     * @throws BadPaddingException
     *                 if this cipher is in decryption mode, and (un)padding has
     *                 been requested, but the decrypted data is not bounded by
     *                 the appropriate padding bytes.
     */
    public final int doFinal(byte[] output, int outputOffset)
	    throws IllegalStateException, IllegalBlockSizeException,
	    ShortBufferException, BadPaddingException {
	if (!init_) {
	    throw new IllegalStateException("not initialised");
	}
	checkOutputParameters(output, outputOffset);

	return cipherSpi_.engineDoFinal(null, 0, 0, output, outputOffset);
    }

    /**
     * Encrypts or decrypts data in a single-part operation, or finishes a
     * multiple-part operation. The data is encrypted or decrypted, depending on
     * how this cipher was initialized.
     * 
     * <p>
     * The bytes in the <tt>input</tt> buffer, and any input bytes that may
     * have been buffered during a previous <tt>update</tt> operation, are
     * processed, with padding (if requested) being applied. The result is
     * stored in a new buffer.
     * 
     * <p>
     * A call to this method resets this cipher object to the state it was in
     * when previously initialized via a call to <tt>init</tt>. That is, the
     * object is reset and available to encrypt or decrypt (depending on the
     * operation mode that was specified in the call to <tt>init</tt>) more
     * data.
     * 
     * @param input
     *                the input buffer.
     * @return The new buffer with the result.
     * @throws IllegalStateException
     *                 if this cipher is in a wrong state (e.g., has not been
     *                 initialized).
     * @throws IllegalBlockSizeException
     *                 if this cipher is a block cipher, no padding has been
     *                 requested (only in encryption mode), and the total input
     *                 length of the data processed by this cipher is not a
     *                 multiple of block size.
     * @throws BadPaddingException
     *                 if this cipher is in decryption mode, and (un)padding has
     *                 been requested, but the decrypted data is not bounded by
     *                 the appropriate padding bytes.
     */
    public final byte[] doFinal(byte[] input) throws IllegalStateException,
	    IllegalBlockSizeException, BadPaddingException {
	return doFinal(input, 0, input.length);
    }

    /**
     * Encrypts or decrypts data in a single-part operation, or finishes a
     * multiple-part operation. The data is encrypted or decrypted, depending on
     * how this cipher was initialized.
     * 
     * <p>
     * The first <tt>inputLen</tt> bytes in the <tt>input</tt> buffer,
     * starting at <tt>inputOffset</tt> inclusive, and any input bytes that
     * may have been buffered during a previous <tt>update</tt> operation, are
     * processed, with padding (if requested) being applied. The result is
     * stored in a new buffer.
     * 
     * <p>
     * A call to this method resets this cipher object to the state it was in
     * when previously initialized via a call to <tt>init</tt>. That is, the
     * object is reset and available to encrypt or decrypt (depending on the
     * operation mode that was specified in the call to <tt>init</tt>) more
     * data.
     * 
     * @param input
     *                The input buffer.
     * @param inputOffset
     *                The offset in <tt>input</tt> where the input starts.
     * @param inputLen
     *                The input length.
     * @return The new buffer with the result.
     * @throws IllegalStateException
     *                 if this cipher is in a wrong state (e.g., has not been
     *                 initialized).
     * @throws IllegalBlockSizeException
     *                 if this cipher is a block cipher, no padding has been
     *                 requested (only in encryption mode), and the total input
     *                 length of the data processed by this cipher is not a
     *                 multiple of block size.
     * @throws BadPaddingException
     *                 if this cipher is in decryption mode, and (un)padding has
     *                 been requested, but the decrypted data is not bounded by
     *                 the appropriate padding bytes.
     */
    public final byte[] doFinal(byte[] input, int inputOffset, int inputLen)
	    throws IllegalStateException, IllegalBlockSizeException,
	    BadPaddingException {
	if (!init_) {
	    throw new IllegalStateException("not initialised");
	}
	checkInputParameters(input, inputOffset, inputLen);

	return cipherSpi_.engineDoFinal(input, inputOffset, inputLen);
    }

    /**
     * Finishes a multiple-part encryption or decryption operation, depending on
     * how this cipher was initialized.
     * 
     * <p>
     * Input data that may have been buffered during a previous <tt>update</tt>
     * operation is processed, with padding (if requested) being applied. The
     * result is stored in a new buffer.
     * 
     * <p>
     * If the <tt>output</tt> buffer is too small to hold the result, a
     * <tt>ShortBufferException</tt> is thrown. In this case, repeat this call
     * with a larger output buffer. Use <tt>getOutputSize()</tt> to determine
     * how big the output buffer should be.
     * 
     * <p>
     * A call to this method resets this cipher object to the state it was in
     * when previously initialized via a call to <tt>init</tt>. That is, the
     * object is reset and available to encrypt or decrypt (depending on the
     * operation mode that was specified in the call to <tt>init</tt>) more
     * data.
     * 
     * @param input
     *                The input buffer.
     * @param inputOffset
     *                The offset in input where the input starts.
     * @param inputLen
     *                The input length.
     * @param output
     *                The buffer for the result.
     * @return The number of bytes stored in output.
     * @throws IllegalStateException
     *                 if this cipher is in a wrong state (e.g., has not been
     *                 initialized).
     * @throws IllegalBlockSizeException
     *                 if this cipher is a block cipher, no padding has been
     *                 requested (only in encryption mode), and the total input
     *                 length of the data processed by this cipher is not a
     *                 multiple of block size.
     * @throws ShortBufferException
     *                 if the given output buffer is too small to hold the
     *                 result.
     * @throws BadPaddingException
     *                 if this cipher is in decryption mode, and (un)padding has
     *                 been requested, but the decrypted data is not bounded by
     *                 the appropriate padding bytes.
     */
    public final int doFinal(byte[] input, int inputOffset, int inputLen,
	    byte[] output) throws IllegalStateException, ShortBufferException,
	    IllegalBlockSizeException, BadPaddingException {
	return doFinal(input, inputOffset, inputLen, output, 0);
    }

    /**
     * Finishes a multiple-part encryption or decryption operation, depending on
     * how this cipher was initialized.
     * 
     * <p>
     * Input data that may have been buffered during a previous <tt>update</tt>
     * operation is processed, with padding (if requested) being applied. The
     * result is stored in a new buffer.
     * 
     * <p>
     * If the <tt>output</tt> buffer is too small to hold the result, a
     * <tt>ShortBufferException</tt> is thrown. In this case, repeat this call
     * with a larger output buffer. Use <tt>getOutputSize()</tt> to determine
     * how big the output buffer should be.
     * 
     * <p>
     * A call to this method resets this cipher object to the state it was in
     * when previously initialized via a call to <tt>init</tt>. That is, the
     * object is reset and available to encrypt or decrypt (depending on the
     * operation mode that was specified in the call to <tt>init</tt>) more
     * data.
     * 
     * @param input
     *                The input buffer.
     * @param inputOffset
     *                The offset in input where the input starts.
     * @param inputLen
     *                The input length.
     * @param output
     *                the buffer for the result.
     * @param outputOffset
     *                the offset in <tt>output</tt> where the result is
     *                stored.
     * @return The number of bytes stored in output.
     * @throws IllegalStateException
     *                 if this cipher is in a wrong state (e.g., has not been
     *                 initialized).
     * @throws IllegalBlockSizeException
     *                 if this cipher is a block cipher, no padding has been
     *                 requested (only in encryption mode), and the total input
     *                 length of the data processed by this cipher is not a
     *                 multiple of block size.
     * @throws ShortBufferException
     *                 if the given output buffer is too small to hold the
     *                 result.
     * @throws BadPaddingException
     *                 if this cipher is in decryption mode, and (un)padding has
     *                 been requested, but the decrypted data is not bounded by
     *                 the appropriate padding bytes.
     */
    public final int doFinal(byte[] input, int inputOffset, int inputLen,
	    byte[] output, int outputOffset) throws IllegalStateException,
	    ShortBufferException, IllegalBlockSizeException,
	    BadPaddingException {
	if (!init_) {
	    throw new IllegalStateException("not initialised");
	}
	checkInputParameters(input, inputOffset, inputLen);
	checkOutputParameters(output, outputOffset);

	return cipherSpi_.engineDoFinal(input, inputOffset, inputLen, output,
		outputOffset);
    }

    private void checkInputParameters(byte[] input, int inputOffset,
	    int inputLen) {
	// --rpw 2001/10/04 this caused all our headaches with PBE
	// if (input == null)
	// {
	// throw new NullPointerException("input");
	// }
	if (inputOffset < 0) {
	    throw new IllegalArgumentException("input offset is < 0");
	}
	if (inputLen < 0) {
	    throw new IllegalArgumentException("input length < 0");
	}
	if (input != null && inputLen > (input.length - inputOffset)) {
	    throw new IllegalArgumentException(
		    "input buffer too small for given length and offset");
	}
    }

    private void checkOutputParameters(byte[] output, int outputOffset) {
	if (output == null) {
	    throw new NullPointerException("output");
	}
	if (outputOffset < 0) {
	    throw new IllegalArgumentException("output offset is < 0");
	}
	if (output.length <= outputOffset) {
	    throw new IllegalArgumentException(
		    "output buffer too small for given offset");
	}
    }

    public final String toString() {
	return "Cipher(\"" + provider_.getName() + "\", \"" + transformation_
		+ "\")";
    }
}
