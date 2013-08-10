/* Copyright 2000 Fraunhofer Gesellschaft
 * Leonrodstr. 54, 80636 Munich, Germany.
 * All rights reserved.
 *
 * You shall use this software only in accordance with
 * the terms of the license agreement you entered into
 * with Fraunhofer Gesellschaft.
 */
package javax.crypto;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * A CipherOutputStream is composed of an OutputStream and a Cipher so that
 * write() methods first process the data before writing them out to the
 * underlying OutputStream. The cipher must be fully initialized before being
 * used by a CipherOutputStream.
 * 
 * <p>
 * For example, if the cipher is initialized for encryption, the
 * CipherOutputStream will attempt to encrypt data before writing out the
 * encrypted data.
 * 
 * <p>
 * This class adheres strictly to the semantics, especially the failure
 * semantics, of its ancestor classes java.io.OutputStream and
 * java.io.FilterOutputStream. This class has exactly those methods specified in
 * its ancestor classes, and overrides them all. Moreover, this class catches
 * all exceptions that are not thrown by its ancestor classes.
 * 
 * <p>
 * It is crucial for a programmer using this class not to use methods that are
 * not defined or overriden in this class (such as a new method or constructor
 * that is later added to one of the super classes), because the design and
 * implementation of those methods are unlikely to have considered security
 * impact with regard to CipherOutputStream.
 * <P>
 * <DL>
 * <DT><B>Since: </B>
 * <DD>JCE1.2</DD>
 * <DT><B>See Also: </B>
 * <DD><CODE>OutputStream</CODE>, <CODE>FilterOutputStream</CODE>,
 * <CODE>Cipher</CODE>, <CODE>CipherInputStream</CODE>
 * </DL>
 * 
 * @author Patric Kabus
 * @version $Id: CipherOutputStream.java,v 1.1.1.1 2001/05/15 11:59:09 krprvadm
 *          Exp $
 */
public class CipherOutputStream extends FilterOutputStream {
    /**
     * The cipher used by this instance.
     */
    private Cipher cipher_;

    /**
     * Constructs a CipherOutputStream from an OutputStream and a Cipher.
     * 
     * @param os
     *                the OutputStream
     * @param c
     *                the Cipher
     */
    public CipherOutputStream(OutputStream os, Cipher c) {
	super(os);
	if (c == null) {
	    throw new NullPointerException("c");
	}
	cipher_ = c;
    }

    /**
     * Constructs a CipherOutputStream from an OutputStream without specifying a
     * Cipher. This has the effect of constructing a CipherOutputStream using a
     * NullCipher.
     * 
     * @param os
     *                the OutputStream
     */
    protected CipherOutputStream(OutputStream os) {
	this(os, new NullCipher());
    }

    /**
     * Writes the specified byte to this output stream.
     * 
     * @param b
     *                The <code>byte</code>.
     * @exception IOException
     *                    if an I/O error occurs.
     */
    public void write(int b) throws IOException {
	byte[] buf;

	buf = new byte[1];
	buf[0] = (byte) b;
	write(buf, 0, 1);
    }

    /**
     * Writes <code>b.length</code> bytes from the specified byte array to
     * this output stream.
     * 
     * <p>
     * The <code>write</code> method of <code>CipherOutputStream</code>
     * calls the <code>write</code> method of three arguments with the three
     * arguments <code>b</code>, <code>0</code>, and <code>b.length</code>.
     * 
     * @param b
     *                The data.
     * @exception IOException
     *                    if an I/O error occurs.
     */
    public void write(byte[] b) throws IOException {
	write(b, 0, b.length);
    }

    /**
     * Writes <code>len</code> bytes from the specified byte array starting at
     * offset <code>off</code> to this output stream.
     * 
     * @param b
     *                The data.
     * @param off
     *                The start offset in the data.
     * @param len
     *                The number of bytes to write.
     * @exception IOException
     *                    if an I/O error occurs.
     */
    public void write(byte[] b, int off, int len) throws IOException {
	byte[] buf;

	if (b == null) {
	    throw new NullPointerException("b");
	}
	if (off < 0) {
	    throw new IllegalArgumentException("offset is <0");
	}
	if (len < 0) {
	    throw new IllegalArgumentException("length is < 0");
	}
	if (len > (b.length - off)) {
	    throw new ArrayIndexOutOfBoundsException(
		    "input buffer too small for given length and offset");
	}
	buf = cipher_.update(b, off, len);
	if (buf != null) {
	    out.write(buf, 0, buf.length);
	}
    }

    /**
     * Flushes this output stream by forcing any buffered output bytes that have
     * already been processed by the encapsulated cipher object to be written
     * out.
     * 
     * <p>
     * Any bytes buffered by the encapsulated cipher and waiting to be processed
     * by it will not be written out. For example, if the encapsulated cipher is
     * a block cipher, and the total number of bytes written using one of the
     * <code>write</code> methods is less than the cipher's block size, no
     * bytes will be written out.
     * 
     * @exception IOException
     *                    if an I/O error occurs.
     */
    public void flush() throws IOException {
	out.flush();
    }

    /**
     * Closes this output stream and releases any system resources associated
     * with this stream.
     * 
     * <p>
     * This method invokes the <code>doFinal</code> method of the encapsulated
     * cipher object, which causes any bytes buffered by the encapsulated cipher
     * to be processed. The result is written out by calling the
     * <code>flush</code> method of this output stream.
     * 
     * <p>
     * This method resets the encapsulated cipher object to its initial state
     * and calls the <code>close</code> method of the underlying output
     * stream.
     * 
     * @exception IOException
     *                    if an I/O error occurs.
     */
    public void close() throws IOException {
	byte[] buf;

	try {
	    buf = cipher_.doFinal();
	    out.write(buf, 0, buf.length);
	} catch (Exception e) {
	    throw new IOException(e.toString());
	}
	out.flush();
	out.close();
    }
}
