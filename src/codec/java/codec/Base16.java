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
 * If there's Base64, why shouldn't there be Base16 as well? Simple and plain,
 * not hexadecimal, but based on letters.
 * 
 * @author Volker Roth
 * @version "$Id: Base16.java,v 1.3 2005/03/22 13:19:35 flautens Exp $"
 */

public final class Base16 extends Object {

    /**
     * This class is never instantiated; use the class methods instead.
     */
    private Base16() {
    }

    /**
     * The basic Base64 encoding table. The index into the string is the value
     * being encoded with the corresponding character.
     */
    private static final char[] BASE16_ = new String(
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZ").toCharArray();

    /**
     * Marks an entry in the decoding table as an invalid code character.
     */
    private static final byte F = (byte) 255;

    /**
     * The table <code>reverse</code> serves to transform encoded characters
     * back into the corresponding six bit values efficiently.
     */
    private static final byte[] REVERSE_ = { F, F, F, F, F, F, F, F, F, F, F,
	    F, F, F, F, F, F, F, F, F, F, F, F, F, F, F, F, F, F, F, F, F, F,
	    F, F, F, F, F, F, F, F, F, F, F, F, F, F, F, F, F, F, F, F, F, F,
	    F, F, F, F, F, F, F, F, F, F, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
	    12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
	    F, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2,
	    3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 };

    /**
     * Encodes the input array of bytes into a Base16 encoded string.
     * 
     * @param input
     *                The byte array to be encoded.
     * @return The Base64 encoded String representing the input byte array.
     */
    public static String encode(byte[] input) {
	StringBuffer output;
	int i, m;
	int a;

	if (input.length == 0) {
	    return "";
	}
	/*
	 * Compute the length of the output buffer.
	 */
	output = new StringBuffer(2 * input.length);

	for (i = 0; i < input.length; i++) {
	    a = input[i];

	    m = (a >>> 4) & 15;
	    output.append(BASE16_[m]);

	    m = a & 15;
	    output.append(BASE16_[m]);
	}
	return output.toString();
    }

    /**
     * Decodes a Base64 encoded string into an array of bytes with exactly the
     * length of the encoded data. The encoded string may contain arbitrarily
     * much garbage data in the form of control sequences and non-base64
     * characters as long as the local charcter encoding is Unicode BASE_LATIN.
     * <p>
     * 
     * @param input
     *                The encoded Base64 character String.
     * @return The decoded data.
     * @throws CorruptedCodeException
     *                 if the Base64 code contains errors such as a missing
     *                 character or bad padding.
     */
    public static byte[] decode(String input) throws CorruptedCodeException {
	byte[] buf;
	int a;
	int b;
	int j;
	int n;

	if (input.length() == 0) {
	    return new byte[0];
	}
	n = input.length();

	if (n % 2 == 1) {
	    throw new CorruptedCodeException("uneven input length");
	}
	n = n / 2;
	buf = new byte[n];

	for (j = 0, n = 0; n < buf.length; n++) {
	    a = input.charAt(j++) & 255;
	    a = REVERSE_[a];
	    b = input.charAt(j++) & 255;
	    b = REVERSE_[b];

	    if (a == F || b == F) {
		throw new CorruptedCodeException("illegal char");
	    }
	    buf[n] = (byte) ((a << 4) | b);
	}
	return buf;
    }

    public static void main(String[] argv) {
	try {
	    System.out.println(Base16.encode(Base16.decode("DEADcafe")));
	} catch (Exception e) {
	    e.printStackTrace();
	}
    }

}
