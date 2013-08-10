/* ========================================================================
 *
 *  This file is part of CODEC, which is a Java package for encoding
 *  and decoding ASN.1 data structures.
 *
 *  Author: Fraunhofer Institute for Computer Graphics Research IGD
 *          Department A8: Security Technology
 *          Fraunhoferstr. 5, 64283 Darmstadt, Germany
 *
 *  Rights: Copyright (c) 2004 by Fraunhofer-Gesellschaft 
 *          zur Foerderung der angewandten Forschung e.V.
 *          Hansastr. 27c, 80686 Munich, Germany.
 *
 * ------------------------------------------------------------------------
 *
 *  The software package is free software; you can redistribute it and/or 
 *  modify it under the terms of the GNU Lesser General Public License as 
 *  published by the Free Software Foundation; either version 2.1 of the 
 *  License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful, but 
 *  WITHOUT ANY WARRANTY; without even the implied warranty of 
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public 
 *  License along with this software package; if not, write to the Free 
 *  Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, 
 *  MA 02110-1301, USA or obtain a copy of the license at 
 *  http://www.fsf.org/licensing/licenses/lgpl.txt.
 *
 * ------------------------------------------------------------------------
 *
 *  The CODEC library can solely be used and distributed according to 
 *  the terms and conditions of the GNU Lesser General Public License for 
 *  non-commercial research purposes and shall not be embedded in any 
 *  products or services of any user or of any third party and shall not 
 *  be linked with any products or services of any user or of any third 
 *  party that will be commercially exploited.
 *
 *  The CODEC library has not been tested for the use or application 
 *  for a determined purpose. It is a developing version that can 
 *  possibly contain errors. Therefore, Fraunhofer-Gesellschaft zur 
 *  Foerderung der angewandten Forschung e.V. does not warrant that the 
 *  operation of the CODEC library will be uninterrupted or error-free. 
 *  Neither does Fraunhofer-Gesellschaft zur Foerderung der angewandten 
 *  Forschung e.V. warrant that the CODEC library will operate and 
 *  interact in an uninterrupted or error-free way together with the 
 *  computer program libraries of third parties which the CODEC library 
 *  accesses and which are distributed together with the CODEC library.
 *
 *  Fraunhofer-Gesellschaft zur Foerderung der angewandten Forschung e.V. 
 *  does not warrant that the operation of the third parties's computer 
 *  program libraries themselves which the CODEC library accesses will 
 *  be uninterrupted or error-free.
 *
 *  Fraunhofer-Gesellschaft zur Foerderung der angewandten Forschung e.V. 
 *  shall not be liable for any errors or direct, indirect, special, 
 *  incidental or consequential damages, including lost profits resulting 
 *  from the combination of the CODEC library with software of any user 
 *  or of any third party or resulting from the implementation of the 
 *  CODEC library in any products, systems or services of any user or 
 *  of any third party.
 *
 *  Fraunhofer-Gesellschaft zur Foerderung der angewandten Forschung e.V. 
 *  does not provide any warranty nor any liability that utilization of 
 *  the CODEC library will not interfere with third party intellectual 
 *  property rights or with any other protected third party rights or will 
 *  cause damage to third parties. Fraunhofer Gesellschaft zur Foerderung 
 *  der angewandten Forschung e.V. is currently not aware of any such 
 *  rights.
 *
 *  The CODEC library is supplied without any accompanying services.
 *
 * ========================================================================
 */
package codec;

import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;

/**
 * This class provides efficient UTF8 reading capability as a sub-class of
 * <code>java.io.Reader</code>. It is able to buffer, and translate from an
 * UTF8 input stream to Unicode characters. Method <code>readLine()</code> can
 * return a single line of material as a Java string.
 * 
 * For best performance, call <code>new UTF8InputStreamReader(in, 2048)</code>
 * instead of <code>new BufferedReader(new InputStreamReader(new
 *   BufferedInputStream(in, 2048), "UTF8" ), 1)</code>
 */
public class UTF8InputStreamReader extends Reader {
    protected int numbytes_ = 0;
    protected int hasExtra_ = 0;
    protected char extraCh_ = 0;
    protected int byteptr_ = 0;
    protected InputStream ins_;
    protected byte[] bytebuf_;

    /**
     * This constructor initializes an UTF8InputStreamReader.
     * 
     * @param i
     *                the InputStream object from which the input will be read.
     * @param bufsize
     *                the size which must be buffered.
     */
    public UTF8InputStreamReader(InputStream i, int bufsize) {
	/*
	 * bufsize of 8192 bytes would be good, no need to wrap in a buffered
	 * reader
	 */
	ins_ = i;
	bytebuf_ = new byte[bufsize];
    }

    public String getEncoding() {
	return "UTF8";
    }

    /**
     * Checks whether the InputStream, with which this object is initialized, is
     * initialized.
     * 
     * @throws IOException
     *                 if the InputStream is <code>null</code>
     */
    protected void checkOpen() throws IOException {
	if (ins_ == null) {
	    throw new IOException("Stream closed");
	}
    }

    /**
     * @see java.io.Reader#read()
     */
    public int read() throws IOException {
	synchronized (lock) {
	    return translate();
	}
    }

    /**
     * @see java.io.Reader#read(char[], int, int)
     */
    public int read(char cbuf[], int off, int len) throws IOException {
	int result;
	int end;
	int ch;

	end = off + len;

	if ((len < 0) || (off < 0) || (cbuf.length < off) || (end < 0)
		|| (cbuf.length < end)) {
	    throw new IndexOutOfBoundsException();
	}
	result = 0;

	synchronized (lock) {
	    checkOpen();

	    if (len == 0) {
		return 0;
	    }

	    for (; len > 0; --len) {
		ch = translate();

		if (ch < 0) {
		    break;
		}
		cbuf[off++] = (char) ch;
		++result;
	    }
	}
	return (result == 0) ? -1 : result;
    }

    /**
     * Read from UTF8 stream until end of line, and return the content as a Java
     * String. A line is considered to be terminated by any one of a line feed
     * ('\n'), a carriage return ('\r'), or a carriage return followed by a
     * linefeed.
     * 
     * @return A String containing the contents of the line, not including any
     *         line-termination characters, or null if the end of the stream has
     *         been reached.
     * 
     * @throws IOException
     *                 if an I/O error occurs.
     */
    public String readLine() throws IOException {
	StringBuffer s;
	int ch2;
	int ch;

	s = null;

	synchronized (lock) {
	    checkOpen();

	    for (;;) {
		ch = translate();

		if (ch < 0) // eof
		{
		    return (s == null) ? null : s.toString();
		}

		if (ch == '\n') {
		    break;
		}
		if (ch == '\r') {
		    ch2 = translate();
		    if ((ch2 != '\n') && (ch2 >= 0)) {
			hasExtra_ = 1;
			// put back
			extraCh_ = (char) ch2;
		    }
		    break;
		}
		if (s == null) {
		    s = new StringBuffer(80);
		}
		s.append((char) ch);
	    }
	}
	return (s == null) ? "" : s.toString();
    }

    /**
     * @see java.io.Reader#ready()
     */
    public boolean ready() throws IOException {
	synchronized (lock) {
	    checkOpen();

	    try {
		return (hasExtra_ > 0) || (numbytes_ > byteptr_)
			|| (ins_.available() > 0);
	    } catch (IOException e1) {
		return false;
	    }
	}
    }

    public void close() throws IOException {
	synchronized (lock) {
	    if (ins_ != null) {
		ins_.close();
		ins_ = null;
		bytebuf_ = null;
	    }
	}
    }

    private int morebyte() throws IOException {
	if (byteptr_ < numbytes_) {
	    return 0xff & bytebuf_[byteptr_++];
	}
	byteptr_ = 0;

	// fill buffer from underlying stream
	numbytes_ = ins_.read(bytebuf_);

	if (numbytes_ > 0) {
	    return 0xff & bytebuf_[byteptr_++];
	}
	numbytes_ = 0;

	// hit EOF
	return -1;
    }

    private int translate() throws IOException {
	int char1;
	int char2;
	int char3;
	int char4;
	int a4;

	if (hasExtra_ > 0) {
	    hasExtra_ = 0;
	    return extraCh_;
	}
	char1 = morebyte();

	if (char1 < 0) {
	    // EOF
	    return char1;
	}

	if (0 == (char1 & 0x80)) {
	    // 1 byte UTF
	    return char1;
	}

	switch (char1 >> 4) {
	case 0xc:

	case 0xd:
	    char2 = morebyte();
	    if (char2 < 0) {
		// EOF
		characterDecodingException();
	    }

	    if ((char2 & 0xc0) != 0x80) {
		characterDecodingException();
	    }
	    // 2 byte UTF
	    return ((char1 & 0x1f) << 6) | (char2 & 0x3f);

	case 0xe:
	    char2 = morebyte();

	    if (char2 < 0) {
		// EOF
		characterDecodingException();
	    }

	    char3 = morebyte();

	    if (char3 < 0) {
		// EOF
		characterDecodingException();
	    }

	    if (((char2 & 0xc0) != 0x80) || ((char3 & 0xc0) != 0x80)) {
		// EOF
		characterDecodingException();
	    }
	    // 3 byte UTF
	    return ((char1 & 0xf) << 12) | ((char2 & 0x3f) << 6)
		    | (char3 & 0x3f);

	case 0xf: {
	    // 4 byte UTF
	    char2 = morebyte();

	    if (char2 < 0) {
		// EOF
		characterDecodingException();
	    }

	    char3 = morebyte();
	    if (char3 < 0) {
		// EOF
		characterDecodingException();
	    }

	    char4 = morebyte();
	    if (char4 < 0) {
		// EOF
		characterDecodingException();
	    }

	    if (((char2 & 0xc0) != 0x80) || ((char3 & 0xc0) != 0x80)
		    || ((char4 & 0xc0) != 0x80)) {
		// EOF
		characterDecodingException();
	    }
	    a4 = ((char1 & 0x7) << 18) | ((char2 & 0x3f) << 12)
		    | ((char3 & 0x3f) << 6) | (char4 & 0x3f);

	    hasExtra_ = 1;
	    extraCh_ = (char) ((a4 - 0x10000) % 0x400 + 0xdc00);

	    return (char) ((a4 - 0x10000) / 0x400 + 0xd800);
	}
	default:
	    throw new IOException("Character decoding exception.");
	}
    }

    protected void characterDecodingException() throws IOException {
	throw new IOException("Character decoding exception.");
    }
}
