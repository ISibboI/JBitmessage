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
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * This class defines the <i>Service Provider Interface</i> (<b>SPI</b>) for
 * the <code>Cipher</code> class. All the abstract methods in this class must
 * be implemented by each cryptographic service provider who wishes to supply
 * the implementation of a particular cipher algorithm.
 * 
 * <p>
 * In order to create an instance of <code>Cipher</code>, which encapsulates
 * an instance of this <code>CipherSpi</code> class, an application calls one
 * of the <a href = "Cipher.html#getInstance(java.lang.String)">getInstance</a>
 * factory methods of the <a href = "Cipher.html">Cipher</a> engine class and
 * specifies the requested <i>transformation</i>. Optionally, the application
 * may also specify the name of a provider.
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
 * A provider may supply a separate class for each combination of
 * <i>algorithm/mode/padding</i>, or may decide to provide more generic classes
 * representing sub-transformations corresponding to <i>algorithm</i> or
 * <i>algorithm/mode</i> or <i>algorithm//padding</i> (note the double
 * slashes), in which case the requested mode and/or padding are set
 * automatically by the <code>getInstance</code> methods of
 * <code>Cipher</code>, which invoke the <a href =
 * "#engineSetMode(java.lang.String)">engineSetMode</a> and <a href =
 * "#engineSetPadding(java.lang.String)">engineSetPadding</a> methods of the
 * provider's subclass of <code>CipherSpi</code>.
 * 
 * <p>
 * A <code>Cipher</code> property in a provider master class may have one of
 * the following formats:
 * 
 * <ul>
 * 
 * <li>
 * 
 * <pre>
 * // provider's subclass of &quot;CipherSpi&quot; implements &quot;algName&quot; with
 * // pluggable mode and padding
 * <code>
 * Cipher.
 * </code>
 * &lt;i&gt;algName&lt;/i&gt;
 * </pre>
 * 
 * <li>
 * 
 * <pre>
 * // provider's subclass of &quot;CipherSpi&quot; implements &quot;algName&quot; in the
 * // specified &quot;mode&quot;, with pluggable padding
 * <code>
 * Cipher.
 * </code>
 * &lt;i&gt;algName/mode&lt;/i&gt;
 * </pre>
 * 
 * <li>
 * 
 * <pre>
 * // provider's subclass of &quot;CipherSpi&quot; implements &quot;algName&quot; with the
 * // specified &quot;padding&quot;, with pluggable mode
 * <code>
 * Cipher.
 * </code>
 * &lt;i&gt;algName//padding&lt;/i&gt;
 * </pre>
 * 
 * <li>
 * 
 * <pre>
 * // provider's subclass of &quot;CipherSpi&quot; implements &quot;algName&quot; with the
 * // specified &quot;mode&quot; and &quot;padding&quot;
 * <code>
 * Cipher.
 * </code>
 * &lt;i&gt;algName/mode/padding&lt;/i&gt;
 * </pre>
 * 
 * </ul>
 * 
 * <p>
 * For example, a provider may supply a subclass of <code>CipherSpi</code>
 * that implements <i>DES/ECB/PKCS5Padding</i>, one that implements
 * <i>DES/CBC/PKCS5Padding</i>, one that implements <i>DES/CFB/PKCS5Padding</i>,
 * and yet another one that implements <i>DES/OFB/PKCS5Padding</i>. That
 * provider would have the following <code>Cipher</code> properties in its
 * master class:
 * <p>
 * 
 * <ul>
 * 
 * <li>
 * 
 * <pre>
 *     <code>
 * Cipher.
 * </code>
 * &lt;i&gt;DES/ECB/PKCS5Padding&lt;/i&gt;
 * </pre>
 * 
 * <li>
 * 
 * <pre>
 *     <code>
 * Cipher.
 * </code>
 * &lt;i&gt;DES/CBC/PKCS5Padding&lt;/i&gt;
 * </pre>
 * 
 * <li>
 * 
 * <pre>
 *     <code>
 * Cipher.
 * </code>
 * &lt;i&gt;DES/CFB/PKCS5Padding&lt;/i&gt;
 * </pre>
 * 
 * <li>
 * 
 * <pre>
 *     <code>
 * Cipher.
 * </code>
 * &lt;i&gt;DES/OFB/PKCS5Padding&lt;/i&gt;
 * </pre>
 * 
 * </ul>
 * 
 * <p>
 * Another provider may implement a class for each of the above modes (i.e., one
 * class for <i>ECB</i>, one for <i>CBC</i>, one for <i>CFB</i>, and one for
 * <i>OFB</i>), one class for <i>PKCS5Padding</i>, and a generic <i>DES</i>
 * class that subclasses from <code>CipherSpi</code>. That provider would
 * have the following <code>Cipher</code> properties in its master class:
 * <p>
 * 
 * <ul>
 * 
 * <li>
 * 
 * <pre>
 *     <code>
 * Cipher.
 * </code>
 * &lt;i&gt;DES&lt;/i&gt;
 * </pre>
 * 
 * </ul>
 * 
 * <p>
 * The <code>getInstance</code> factory method of the <code>Cipher</code>
 * engine class follows these rules in order to instantiate a provider's
 * implementation of <code>CipherSpi</code> for a transformation of the form "<i>algorithm</i>":
 * 
 * <ol>
 * <li> Check if the provider has registered a subclass of
 * <code>CipherSpi</code> for the specified "<i>algorithm</i>".
 * <p>
 * If the answer is YES, instantiate this class, for whose mode and padding
 * scheme default values (as supplied by the provider) are used.
 * <p>
 * If the answer is NO, throw a <code>NoSuchAlgorithmException</code>
 * exception.
 * </ol>
 * 
 * <p>
 * The <code>getInstance</code> factory method of the <code>Cipher</code>
 * engine class follows these rules in order to instantiate a provider's
 * implementation of <code>CipherSpi</code> for a transformation of the form "<i>algorithm/mode/padding</i>":
 * 
 * <ol>
 * <li> Check if the provider has registered a subclass of
 * <code>CipherSpi</code> for the specified "<i>algorithm/mode/padding</i>"
 * transformation.
 * <p>
 * If the answer is YES, instantiate it.
 * <p>
 * If the answer is NO, go to the next step.
 * <p>
 * <li> Check if the provider has registered a subclass of
 * <code>CipherSpi</code> for the sub-transformation "<i>algorithm/mode</i>".
 * <p>
 * If the answer is YES, instantiate it, and call
 * <code>engineSetPadding(<i>padding</i>)</code> on the new instance.
 * <p>
 * If the answer is NO, go to the next step.
 * <p>
 * <li> Check if the provider has registered a subclass of
 * <code>CipherSpi</code> for the sub-transformation "<i>algorithm//padding</i>"
 * (note the double slashes).
 * <p>
 * If the answer is YES, instantiate it, and call
 * <code>engineSetMode(<i>mode</i>)</code> on the new instance.
 * <p>
 * If the answer is NO, go to the next step.
 * <p>
 * <li> Check if the provider has registered a subclass of
 * <code>CipherSpi</code> for the sub-transformation "<i>algorithm</i>".
 * <p>
 * If the answer is YES, instantiate it, and call
 * <code>engineSetMode(<i>mode</i>)</code> and
 * <code>engineSetPadding(<i>padding</i>)</code> on the new instance.
 * <p>
 * If the answer is NO, throw a <code>NoSuchAlgorithmException</code>
 * exception.
 * </ol>
 * <P>
 * <DL>
 * <DT><B>See Also: </B>
 * <DD><CODE>KeyGenerator</CODE>, <CODE>SecretKey</CODE>
 * </DL>
 * 
 * @author Patric Kabus
 * @version $Id: CipherSpi.java,v 1.1.1.1 2001/05/15 11:59:09 krprvadm Exp $
 */
public abstract class CipherSpi extends Object {
    public CipherSpi() {
    }

    /**
     * Sets the mode of this cipher.
     * 
     * @param mode
     *                The cipher mode.
     * @exception NoSuchAlgorithmException
     *                    if the requested cipher mode does not exist.
     */
    protected abstract void engineSetMode(String mode)
	    throws NoSuchAlgorithmException;

    /**
     * Sets the padding mechanism of this cipher.
     * 
     * @param padding
     *                the padding mechanism.
     * @exception NoSuchPaddingException
     *                    if the requested padding mechanism does not exist.
     */
    protected abstract void engineSetPadding(String padding)
	    throws NoSuchPaddingException;

    /**
     * Returns the block size (in bytes).
     * 
     * @return The block size (in bytes), or 0 if the underlying algorithm is
     *         not a block cipher.
     */
    protected abstract int engineGetBlockSize();

    /**
     * <DD>Returns the length in bytes that an output buffer would need to be
     * in order to hold the result of the next <code>update</code> or
     * <code>doFinal</code> operation, given the input length
     * <code>inputLen</code> (in bytes).
     * 
     * <p>
     * This call takes into account any unprocessed (buffered) data from a
     * previous <code>update</code> call, and padding.
     * 
     * <p>
     * The actual output length of the next <code>update</code> or
     * <code>doFinal</code> call may be smaller than the length returned by
     * this method.
     * 
     * @param inputLen
     *                The input length (in bytes).
     * @return The required output buffer size (in bytes).
     */
    protected abstract int engineGetOutputSize(int inputLen);

    /**
     * Returns the initialization vector (IV) in a new buffer.
     * 
     * <p>
     * This is useful in the context of password-based encryption or decryption,
     * where the IV is derived from a user-provided passphrase.
     * 
     * @return The initialization vector in a new buffer, or null if the
     *         underlying algorithm does not use an IV, or if the IV has not yet
     *         been set.
     */
    protected abstract byte[] engineGetIV();

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
    protected abstract AlgorithmParameters engineGetParameters();

    /**
     * Initializes this cipher with a key and a source of randomness.
     * 
     * <p>
     * The cipher is initialized for encryption or decryption, depending on the
     * value of <code>opmode</code>.
     * 
     * <p>
     * If this cipher requires any algorithm parameters that cannot be derived
     * from the given <code>key</code>, the underlying cipher implementation
     * is supposed to generate the required parameters itself (using
     * provider-specific default or random values) if it is being initialized
     * for encryption, and raise an <code>InvalidKeyException</code> if it is
     * being initialized for decryption. The generated parameters can be
     * retrieved using <code>engineGetParameters</code> or
     * <code>engineGetIV</code> (if the parameter is an IV).
     * 
     * <p>
     * If this cipher (including its underlying feedback or padding scheme)
     * requires any random bytes (e.g., for parameter generation), it will get
     * them from <code>random</code>.
     * 
     * <p>
     * Note that when a Cipher object is initialized, it loses all
     * previously-acquired state. In other words, initializing a Cipher is
     * equivalent to creating a new instance of that Cipher and initializing it.
     * 
     * @param opmode
     *                The operation mode of this cipher (this is either
     *                <code>ENCRYPT_MODE</code> or <code>DECRYPT_MODE</code>).
     * @param key
     *                The encryption key.
     * @param random
     *                The source of randomness.
     * @exception InvalidKeyException
     *                    if the given key is inappropriate for initializing
     *                    this cipher, or if this cipher is being initialized
     *                    for decryption and requires algorithm parameters that
     *                    cannot be determined from the given key.
     */
    protected abstract void engineInit(int opmode, Key key, SecureRandom random)
	    throws InvalidKeyException;

    /**
     * Initializes this cipher with a key, a set of algorithm parameters, and a
     * source of randomness.
     * 
     * <p>
     * The cipher is initialized for encryption or decryption, depending on the
     * value of <code>opmode</code>.
     * 
     * <p>
     * If this cipher requires any algorithm parameters and <code>params</code>
     * is null, the underlying cipher implementation is supposed to generate the
     * required parameters itself (using provider-specific default or random
     * values) if it is being initialized for encryption, and raise an
     * <code>InvalidAlgorithmParameterException</code> if it is being
     * initialized for decryption. The generated parameters can be retrieved
     * using <code>engineGetParameters</code> or <code>engineGetIV</code>
     * (if the parameter is an IV).
     * 
     * <p>
     * If this cipher (including its underlying feedback or padding scheme)
     * requires any random bytes (e.g., for parameter generation), it will get
     * them from <code>random</code>.
     * 
     * <p>
     * Note that when a Cipher object is initialized, it loses all
     * previously-acquired state. In other words, initializing a Cipher is
     * equivalent to creating a new instance of that Cipher and initializing it.
     * 
     * @param opmode
     *                The operation mode of this cipher (this is either
     *                <code>ENCRYPT_MODE</code> or <code>DECRYPT_MODE</code>).
     * @param key
     *                The encryption key.
     * @param params
     *                The algorithm parameters.
     * @param random
     *                The source of randomness.
     * @exception InvalidKeyException
     *                    if the given key is inappropriate for initializing
     *                    this cipher
     * @exception InvalidAlgorithmParameterException
     *                    if the given algorithm parameters are inappropriate
     *                    for this cipher, or if this cipher is being
     *                    initialized for decryption and requires algorithm
     *                    parameters and <code>params</code> is null.
     */
    protected abstract void engineInit(int opmode, Key key,
	    AlgorithmParameterSpec params, SecureRandom random)
	    throws InvalidKeyException, InvalidAlgorithmParameterException;

    protected abstract void engineInit(int opmode, Key key,
	    AlgorithmParameters params, SecureRandom random)
	    throws InvalidKeyException, InvalidAlgorithmParameterException;

    protected abstract byte[] engineUpdate(byte[] input, int inputOffset,
	    int inputLen);

    protected abstract int engineUpdate(byte[] input, int inputOffset,
	    int inputLen, byte[] output, int outputOffset)
	    throws ShortBufferException;

    protected abstract byte[] engineDoFinal(byte[] input, int inputOffset,
	    int inputLen) throws IllegalBlockSizeException, BadPaddingException;

    protected abstract int engineDoFinal(byte[] input, int inputOffset,
	    int inputLen, byte[] output, int outputOffset)
	    throws ShortBufferException, IllegalBlockSizeException,
	    BadPaddingException;
}
