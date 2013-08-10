/* Copyright 2005 Fraunhofer Gesellschaft
 * Hansastr. 27c, 80686 Munich, Germany.
 * All rights reserved.
 *
 * You shall use this software only in accordance with
 * the terms of the license agreement you entered into
 * with Fraunhofer Gesellschaft.
 */
package javax.crypto;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * A CipherInputStream is composed of an InputStream and a Cipher so that read()
 * methods return data that are read in from the underlying InputStream but have
 * been additionally processed by the Cipher. The Cipher must be fully
 * initialized before being used by a CipherInputStream.
 * 
 * <p>
 * For example, if the Cipher is initialized for decryption, the
 * CipherInputStream will attempt to read in data and decrypt them, before
 * returning the decrypted data.
 * 
 * <p>
 * This class adheres strictly to the semantics, especially the failure
 * semantics, of its ancestor classes java.io.FilterInputStream and
 * java.io.InputStream. This class has exactly those methods specified in its
 * ancestor classes, and overrides them all. Moreover, this class catches all
 * exceptions that are not thrown by its ancestor classes. In particular, the
 * <code>skip</code> method skips, and the <code>available</code> method
 * counts only data that have been processed by the encapsulated Cipher.
 * 
 * <p>
 * It is crucial for a programmer using this class not to use methods that are
 * not defined or overriden in this class (such as a new method or constructor
 * that is later added to one of the super classes), because the design and
 * implementation of those methods are unlikely to have considered security
 * impact with regard to CipherInputStream.
 * <P>
 * <DL>
 * <DT><B>Since: </B>
 * <DD>JCE1.2</DD>
 * <DT><B>See Also: </B>
 * <DD><CODE>InputStream</CODE>, <CODE>FilterInputStream</CODE>,
 * <CODE>Cipher</CODE>, <CODE>CipherOutputStream</CODE>
 * </DL>
 * 
 * @author Patric Kabus
 * @author Jan Peters
 * @version $Id: CipherInputStream.java 1722 2006-04-13 14:57:28Z jpeters $
 */

public class CipherInputStream extends FilterInputStream {

    /**
     * block size in case of _NO BOCK CIPHER_
     */
    private static final int BUFFER_SIZE = 4096;

    /**
     * Current buffer position.
     */
    private int bufferPos_ = 0;

    /**
     * Length of valid data, beginning at the current buffer position.
     */
    private int bufferLen_ = 0;

    /**
     * The cipher being used by this stream.
     */
    private Cipher cipher_;

    /**
     * Indicator that cipher_.doFinal(...) was executed.
     * <p>
     * If <code>true</code> readNextBlock returns -1;
     */
    private boolean isReady_;

    /**
     * Internal write data buffer.
     */
    private byte[] writeBuf_;

    /**
     * Internal read data buffer.
     */
    private byte[] readBuf_;

    /**
     * Constructs a CipherInputStream from an InputStream and a Cipher. If the
     * specified input stream or cipher is null, a NullPointerException is
     * thrown.
     * 
     * @param is
     *                the to-be-processed input stream.
     * @param c
     *                an initialized Cipher object.
     * 
     * @throws NullPointerException
     *                 if <code>c</code> is null.
     */
    public CipherInputStream(InputStream is, Cipher c) {
	super(is);

	this.cipher_ = c;

	bufferLen_ = 0;
	bufferPos_ = 0;

	readBuf_ = new byte[BUFFER_SIZE];

	writeBuf_ = null;
	isReady_ = false;
    }

    /**
     * Constructs a CipherInputStream from an InputStream without specifying a
     * Cipher. This has the effect of constructing a CipherInputStream using a
     * NullCipher.
     * 
     * @param is
     *                the to-be-processed input stream.
     */
    protected CipherInputStream(InputStream is) {
	this(is, new NullCipher());
    }

    /**
     * Reads the next byte of data from this input stream. The value byte is
     * returned as an <code>int</code> in the range <code>0</code> to
     * <code>255</code>. If no byte is available because the end of the
     * stream has been reached, the value <code>-1</code> is returned. This
     * method blocks until input data is available, the end of the stream is
     * detected, or an exception is thrown.
     * 
     * @return The next byte of data, or <code>-1</code> if the end of the
     *         stream is reached.
     * @throws IOException
     *                 if an I/O error occurs.
     */
    public int read() throws IOException {
	if (bufferPos_ >= bufferLen_) {
	    if (readNextBlock() == -1) {
		return -1;
	    }
	}

	return writeBuf_[bufferPos_++] & 0xFF;
    }

    /**
     * Reads up to <code>b.length</code> bytes of data from this input stream
     * into an array of bytes.
     * 
     * <p>
     * The <code>read</code> method of <code>InputStream</code> calls the
     * <code>read</code> method of three arguments with the arguments
     * <code>b</code>, <code>0</code>, and <code>b.length</code>.
     * 
     * @param b
     *                The buffer into which the data is read.
     * @return The total number of bytes read into the buffer, or
     *         <code>-1</code> is there is no more data because the end of the
     *         stream has been reached.
     * @throws IOException
     *                 if an I/O error occurs.
     */
    public int read(byte[] b) throws IOException {
	return read(b, 0, b.length);
    }

    /**
     * Reads up to <code>len</code> bytes of data from this input stream into
     * an array of bytes. This method blocks until some input is available. If
     * the first argument is <code>null,</code> up to <code>len</code> bytes
     * are read and discarded.
     * 
     * @param b
     *                The buffer into which the data is read.
     * @param off
     *                The start offset of the data.
     * @param len
     *                The maximum number of bytes read.
     * 
     * @return The total number of bytes read into the buffer, or
     *         <code>-1</code> if there is no more data because the end of the
     *         stream has been reached.
     * 
     * @throws IOException
     *                 if an I/O error occurs.
     */
    public int read(byte[] b, int off, int len) throws IOException {

	if (b == null || len == 0) {
	    return 0;
	}

	if (b.length < (off + len)) {
	    throw new ArrayIndexOutOfBoundsException(
		    "The buffer is too small for given offset and length!");
	}

	if (bufferPos_ >= bufferLen_) {
	    if (readNextBlock() == -1) {
		return -1;
	    }
	}

	int copied = available();

	if (len <= copied) {
	    System.arraycopy(writeBuf_, bufferPos_, b, off, len);
	    bufferPos_ += len;
	    return len;

	}
	System.arraycopy(writeBuf_, bufferPos_, b, off, copied);
	int read = 0;
	do {
	    read = readNextBlock();
	    if (read < 1) {
		bufferPos_ = bufferLen_;
		return copied;
	    }

	    if (len <= read + copied) {
		System.arraycopy(writeBuf_, bufferPos_, b, off + copied, len
			- copied);
		bufferPos_ += len - (off + copied);
		return len;
	    }

	    // copied = 0;

	    System.arraycopy(writeBuf_, bufferPos_, b, off + copied, read);
	    copied += read;

	} while (true);
    }

    /**
     * Skips <code>n</code> bytes of input from the bytes that can be read
     * from this input stream without blocking.
     * 
     * <p>
     * Fewer bytes than requested might be skipped. The actual number of bytes
     * skipped is equal to <code>n</code> or the result of a call to <a href =
     * "#available()"><code>available</code></a>, whichever is smaller. If
     * <code>n</code> is less than zero, no bytes are skipped.
     * 
     * <p>
     * The actual number of bytes skipped is returned.
     * 
     * @param n
     *                The number of bytes to be skipped.
     * 
     * @return The actual number of bytes skipped.
     */
    public long skip(long n) {
	if (n < 1) {
	    return 0;
	}

	long skip = available();

	if (skip >= n) {
	    bufferPos_ += n;
	    return n;
	}

	bufferPos_ = bufferLen_;
	return skip;
    }

    /**
     * Returns the number of bytes that can be read from this input stream
     * without blocking. The <code>available</code> method of
     * <code>InputStream</code> returns <code>0</code>. This method
     * <B>should</B> be overridden by subclasses.
     * 
     * @return The number of bytes that can be read from this input stream
     *         without blocking.
     */
    public int available() {
	return bufferLen_ - bufferPos_;
    }

    /**
     * Closes this input stream and releases any system resources associated
     * with the stream.
     * 
     * <p>
     * The <code>close</code> method of <code>CipherInputStream</code> calls
     * the <code>close</code> method of its underlying input stream.
     * 
     * @throws IOException
     *                 if an I/O error occurs.
     */
    public void close() throws IOException {
	in.close();
	try {
	    cipher_.doFinal();
	} catch (Exception ex) {
	}
	bufferLen_ = 0;
	bufferPos_ = 0;
    }

    /**
     * Tests if this input stream supports the <code>mark</code> and
     * <code>reset</code> methods, which it does not.
     * 
     * @return <code>false</code>, since this class does not support the
     *         <code>mark</code> and <code>reset</code> methods.
     */
    public boolean markSupported() {
	return false;
    }

    /**
     * Reads and decrypts the next block of data. Note: This method resets the
     * <code>bufferPos_</code> and <code>bufferLen_</code> fields.
     * 
     * @return the number of bytes read.
     * 
     * @throws IOException
     *                 if an error occurs.
     */
    private int readNextBlock() throws IOException {
	try {

	    if (isReady_) {
		return -1;
	    }

	    // int outLen = -1;
	    int read = in.read(readBuf_);

	    if (read == readBuf_.length) {
		writeBuf_ = cipher_.update(readBuf_, 0, read);

		if (writeBuf_ == null || writeBuf_.length == 0) {
		    return readNextBlock();
		}
	    } else if (read > 0) {
		writeBuf_ = cipher_.doFinal(readBuf_, 0, read);

		if (writeBuf_ == null || writeBuf_.length == 0) {
		    return -1;
		}

		isReady_ = true;
	    }

	    // read = outLen;// !isReady ? outLen : buffer_.length;
	    bufferPos_ = 0;
	    bufferLen_ = writeBuf_.length;

	    return writeBuf_.length;
	} catch (Exception e) {
	    throw new IOException(e.toString());
	}
    }

}
