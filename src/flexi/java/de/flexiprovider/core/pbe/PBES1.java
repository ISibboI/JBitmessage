/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.pbe;

import de.flexiprovider.api.BlockCipher;
import de.flexiprovider.api.KeyDerivation;
import de.flexiprovider.api.exceptions.BadPaddingException;
import de.flexiprovider.api.exceptions.IllegalBlockSizeException;
import de.flexiprovider.api.exceptions.NoSuchModeException;
import de.flexiprovider.api.exceptions.NoSuchPaddingException;
import de.flexiprovider.api.exceptions.ShortBufferException;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;

/**
 * This is the base class for all classes which implement passphrase based
 * encryption (PBE). The key derivation function follows the <a
 * href="http://www.rsasecurity.com/rsalabs/pkcs/pkcs-5/index.html">PKCS #5
 * version 2.0</a> standard.
 * 
 * @author Thomas Wahrenbruch
 */
public abstract class PBES1 extends de.flexiprovider.core.pbe.interfaces.PBES1 {

    /**
     * The underlying block cipher (e.g. DES)
     */
    protected BlockCipher cipher;

    /**
     * The underlying key derivation function (PBKDF1 or PBKDF_PKCS12)
     */
    protected KeyDerivation kdf;

    /**
     * Returns the block size (in bytes) of the underlying block cipher.
     * 
     * @return the block size (in bytes), or 0 if the underlying algorithm is
     *         not a block cipher
     */
    public int getBlockSize() {
	return cipher.getBlockSize();
    }

    /**
     * Set the mode for this cipher. This method is not supported and always
     * throws an exception.
     * 
     * @param modeName
     *                the name of the cipher mode
     * @throws NoSuchModeException
     *                 always.
     */
    protected void setMode(String modeName) throws NoSuchModeException {
	throw new NoSuchModeException("unsupported");
    }

    /**
     * Set the padding scheme for this cipher. This method is not supported and
     * always throws an exception.
     * 
     * @param paddingName
     *                the name of the padding scheme
     * @throws NoSuchPaddingException
     *                 always.
     */
    protected void setPadding(String paddingName) throws NoSuchPaddingException {
	throw new NoSuchPaddingException("not supported");
    }

    /**
     * Returns the length in bytes that an output buffer would need to be in
     * order to hold the result of the next update or doFinal operation, given
     * the input length inputLen (in bytes).
     * <p>
     * This call takes into account any unprocessed (buffered) data from a
     * previous update call, and padding.
     * <p>
     * The actual output length of the next update or doFinal call may be
     * smaller than the length returned by this method.
     * 
     * @param inputLen
     *                the input length (in bytes)
     * @return the required output buffer size (in bytes)
     */
    public int getOutputSize(int inputLen) {
	return cipher.getOutputSize(inputLen);
    }

    /**
     * Return the initialization vector. This is useful in the context of
     * password-based encryption or decryption, where the IV is derived from a
     * user-provided passphrase.
     * 
     * @return the initialization vector in a new buffer, or <tt>null</tt> if
     *         the underlying algorithm does not use an IV, or if the IV has not
     *         yet been set.
     */
    public byte[] getIV() {
	return cipher.getIV();
    }

    /**
     * Returns the parameters used with this cipher.
     * <p>
     * The returned parameters may be the same that were used to initialize this
     * cipher, or may contain the default set of parameters or a set of randomly
     * generated parameters used by the underlying cipher implementation
     * (provided that the underlying cipher implementation uses a default set of
     * parameters or creates new parameters if it needs parameters but was not
     * initialized with any).
     * 
     * @return the parameters used with this cipher, or null if this cipher does
     *         not use any parameters.
     */
    public AlgorithmParameterSpec getParameters() {
	return cipher.getParameters();
    }

    /**
     * Continue a multiple-part encryption or decryption operation (depending on
     * how this cipher was initialized), processing another data part.
     * 
     * @param input
     *                the input buffer
     * @param inOff
     *                the offset where the input starts
     * @param inLen
     *                the input length
     * @return a new buffer with the result
     */
    public byte[] update(byte[] input, int inOff, int inLen) {
	return cipher.update(input, inOff, inLen);
    }

    /**
     * Continue a multiple-part encryption or decryption operation (depending on
     * how this cipher was initialized), processing another data part.
     * 
     * @param input
     *                the input buffer
     * @param inOff
     *                the offset where the input starts
     * @param inLen
     *                the input length
     * @param output
     *                the output buffer
     * @param outOff
     *                the offset where the result is stored
     * @return the length of the output
     * @throws ShortBufferException
     *                 if the output buffer is too small to hold the result.
     */
    public int update(byte[] input, int inOff, int inLen, byte[] output,
	    int outOff) throws ShortBufferException {
	return cipher.update(input, inOff, inLen, output, outOff);
    }

    /**
     * Finish a multiple-part encryption or decryption operation (depending on
     * how this cipher was initialized).
     * 
     * @param input
     *                the input buffer
     * @param inOff
     *                the offset where the input starts
     * @param inLen
     *                the input length
     * @return a new buffer with the result
     * @throws IllegalBlockSizeException
     *                 if the total input length is not a multiple of the block
     *                 size (for encryption when no padding is used or for
     *                 decryption).
     * @throws BadPaddingException
     *                 if unpadding fails.
     */
    public byte[] doFinal(byte[] input, int inOff, int inLen)
	    throws IllegalBlockSizeException, BadPaddingException {
	return cipher.doFinal(input, inOff, inLen);
    }

    /**
     * Finish a multiple-part encryption or decryption operation (depending on
     * how this cipher was initialized).
     * 
     * @param input
     *                the input buffer
     * @param inOff
     *                the offset where the input starts
     * @param inLen
     *                the input length
     * @param output
     *                the buffer for the result
     * @param outOff
     *                the offset where the result is stored
     * @return the output length
     * @throws ShortBufferException
     *                 if the output buffer is too small to hold the result.
     * @throws IllegalBlockSizeException
     *                 if the total input length is not a multiple of the block
     *                 size (for encryption when no padding is used or for
     *                 decryption).
     * @throws BadPaddingException
     *                 if unpadding fails.
     */
    public int doFinal(byte[] input, int inOff, int inLen, byte[] output,
	    int outOff) throws ShortBufferException, IllegalBlockSizeException,
	    BadPaddingException {
	return cipher.doFinal(input, inOff, inLen, output, outOff);
    }

}
