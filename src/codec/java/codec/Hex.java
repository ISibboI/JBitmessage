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

/**
 * A converter that converts binary data into strings of hexadecimal characters
 * and vice versa.
 * 
 * @author Volker Roth
 * @version "$Id: Hex.java,v 1.2 2005/04/06 09:31:01 flautens Exp $"
 */
public final class Hex extends Object {
    /**
     * This class is never instantiated; use the class methods instead.
     */
    private Hex() {
    }

    /**
     * The basic Base16 encoding table. The index into the string is the value
     * being encoded with the corresponding character.
     */
    private static final char[] HEX_ = new String("0123456789abcdef")
	    .toCharArray();

    /**
     * Encodes the input array of bytes into a hexadecimal encoded string.
     * 
     * @param in
     *                The byte array to be encoded.
     * @return The hexadecimal encoded String representing the input byte array.
     */
    public static String encode(byte[] in) {
	StringBuffer out;
	int m;
	int n;
	int k;

	if (in.length == 0) {
	    return new String();
	}
	out = new StringBuffer(in.length * 2);

	for (n = 0; n < in.length; n++) {
	    m = in[n];
	    k = (m >>> 4) & 0x0f;

	    out.append(HEX_[k]);

	    k = (m & 0x0f);

	    out.append(HEX_[k]);
	}
	return out.toString();
    }

    /**
     * Decodes a hexadecimal encoded string into an array of bytes with exactly
     * the length of the encoded data.
     * 
     * @param in
     *                The encoded hexadecimal character String.
     * @return The decoded data.
     * @throws CorruptedCodeException
     *                 if the hexadecimal code contains errors such as a missing
     *                 character.
     */
    public static byte[] decode(String in) throws CorruptedCodeException {
	byte[] buf;
	int a;
	int b;
	int j;
	int n;

	if (in.length() == 0) {
	    return new byte[0];
	}
	n = in.length();

	if ((n % 2) == 1) {
	    throw new CorruptedCodeException("uneven input length");
	}
	n = n / 2;
	buf = new byte[n];

	for (j = 0, n = 0; n < buf.length; n++) {
	    a = in.charAt(j++);
	    b = in.charAt(j++);

	    if (('0' <= a) && (a <= '9')) {
		a = a - '0';
	    } else if (('a' <= a) && (a <= 'f')) {
		a = a - 'a' + 10;
	    } else if (('A' <= a) && (a <= 'F')) {
		a = a - 'A' + 10;
	    } else {
		throw new CorruptedCodeException("Illegal char: '" + a + "'");
	    }
	    if (('0' <= b) && (b <= '9')) {
		b = b - '0';
	    } else if (('a' <= b) && (b <= 'f')) {
		b = b - 'a' + 10;
	    } else if (('A' <= b) && (b <= 'F')) {
		b = b - 'A' + 10;
	    } else {
		throw new CorruptedCodeException("Illegal char: '" + b + "'");
	    }
	    buf[n] = (byte) ((a << 4) | b);
	}
	return buf;
    }
}
