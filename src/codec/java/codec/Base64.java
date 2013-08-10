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
 * Encodes and decodes data according to Base64 encoding as described in RFC
 * 1521. Encoded data is broken into lines of 76 charcters each (19 groups of 4
 * characters which represent 3 bytes of input per group.
 * <p>
 * 
 * The three input bytes are divided into four groups of six bits each which are
 * encoded according to the table <code>base64</code> given below.
 * 
 * @author Volker Roth
 * @version "$Id: Base64.java,v 1.5 2005/04/06 09:23:31 flautens Exp $"
 */
public final class Base64 extends Object {
    /**
     * This class is never instantiated; use the class methods instead.
     */
    private Base64() {
    }

    /**
     * The basic Base64 encoding table. The index into the string is the value
     * being encoded with the corresponding character.
     */
    private static final char[] BASE64 = new String(
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "abcdefghijklmnopqrstuvwxyz"
		    + "0123456789+/").toCharArray();

    /**
     * If the input is congruent 2 modulo 3 then one pad character is required.
     */
    private static final char PAD_1 = '=';

    /**
     * If the input is congruent 1 modulo 3 then two pad characters are
     * required.
     */
    private static final String PAD_2 = "==";

    /**
     * Marks an entry in the decoding table as an invalid code character.
     */
    private static final byte F = (byte) 255;

    /**
     * Marks the pad character '=' in the decoding table.
     */
    private static final byte PAD = (byte) 64;

    /**
     * The table <code>reverse</code> serves to transform encoded characters
     * back into the corresponding six bit values efficiently.
     */
    private static final byte[] REVERSE = { F, F, F, F, F, F, F, F, F, F, F, F,
	    F, F, F, F, F, F, F, F, F, F, F, F, F, F, F, F, F, F, F, F, F, F,
	    F, F, F, F, F, F, F, F, F, 62, F, F, F, 63, 52, 53, 54, 55, 56, 57,
	    58, 59, 60, 61, F, F, F, PAD, F, F, F, 0, 1, 2, 3, 4, 5, 6, 7, 8,
	    9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
	    F, F, F, F, F, F, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37,
	    38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, F, F, F, F,
	    F };

    /**
     * Used to transform bytes into a hexadecimal string representation -
     * basically a convenience method which facilitates debugging and
     * verification.
     */
    private static final String HEX = "0123456789abcdef";

    /**
     * Encodes the input array of bytes into a Base64 encoded string with
     * padding if required. The output is <b>not</b> broken into lines.
     * 
     * @param input
     *                The byte array to be encoded.
     * @return The Base64 encoded String representing the input byte array.
     */
    public static String encode(byte[] input) {
	int i;
	int j;
	int m;
	int a;
	int b;
	int c;
	StringBuffer output;

	if (input.length == 0) {
	    return "";
	}

	/*
	 * Compute the length of the output buffer.
	 */
	i = ((input.length + 2) / 3) << 2;
	output = new StringBuffer(i);
	i = input.length / 3;
	j = 0;

	while (i > 0) {
	    a = input[j++];
	    b = input[j++];
	    c = input[j++];

	    m = (a >>> 2) & 63;
	    output.append(BASE64[m]);

	    m = ((a & 3) << 4) | ((b >>> 4) & 15);
	    output.append(BASE64[m]);

	    m = ((b & 15) << 2) | ((c >>> 6) & 3);
	    output.append(BASE64[m]);

	    m = c & 63;
	    output.append(BASE64[m]);
	    i--;
	}
	/*
	 * Handle the padding and encoding of groups of less than three input
	 * bytes length.
	 */
	i = input.length % 3;

	switch (i) {
	case 1:
	    a = input[j++];
	    m = (a >>> 2) & 63;
	    output.append(BASE64[m]);
	    m = (a & 3) << 4;
	    output.append(BASE64[m]);
	    output.append(PAD_2);
	    break;

	case 2:
	    a = input[j++];
	    b = input[j++];
	    m = (a >>> 2) & 63;
	    output.append(BASE64[m]);

	    m = ((a & 3) << 4) | ((b >>> 4) & 15);
	    output.append(BASE64[m]);

	    m = (b & 15) << 2;
	    output.append(BASE64[m]);
	    output.append(PAD_1);
	    break;
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
	int i;
	byte[] b;

	if (input.length() == 0) {
	    return new byte[0];
	}
	b = new byte[input.length()];

	for (i = input.length() - 1; i >= 0; i--) {
	    b[i] = (byte) input.charAt(i);
	}
	return decode(b);
    }

    /**
     * Decodes a given byte array containing Unicode BASE_LATIN encoded
     * characters with one byte encoding per character. <b>The array is garbled
     * in the course of the decoding, because it is partly overwritten with the
     * six Bit groups represented by the code letters!</b> This method is used
     * by the decoding method <code>byte[] decode(String)</code>.
     * 
     * @param code
     *                The BASE_LATIN Base64 encoded input with one byte per
     *                character.
     * @return The byte array containing the decoded data. The array has the
     *         exact length of the decoded data.
     * @throws CorruptedCodeException
     *                 if the decoding process revealed errors such as bad
     *                 padding or missing charcters.
     */
    public static byte[] decode(byte[] code) throws CorruptedCodeException {
	boolean end;
	byte[] output;
	byte m;
	byte a;
	byte b;
	byte c;
	byte d;
	int i;
	int j;
	int k;
	int l;

	l = code.length;
	end = false;

	for (i = 0, j = 0; i < l; i++) {
	    if ((code[i] < 0) || (code[i] >= REVERSE.length)) {
		throw new CorruptedCodeException("Code was not Base64 encoded");
	    }
	    m = REVERSE[code[i]];

	    if (m == PAD) {
		if (end) {
		    break;
		}
		end = true;
		continue;
	    }
	    if (end) {
		throw new CorruptedCodeException(
			"Second pad character missing!");
	    }
	    if (m == F) {
		continue;
	    }
	    code[j++] = m;
	}
	l = j >> 2;
	i = l * 3;
	k = j & 3;

	if (k == 1) {
	    throw new CorruptedCodeException("One character is missing!");
	}
	if (k > 0) {
	    i = (i + k) - 1;
	}
	output = new byte[i];

	i = 0;
	j = 0;
	b = 0;

	while (l > 0) {
	    a = code[i++];
	    b = code[i++];
	    c = code[i++];
	    d = code[i++];

	    output[j++] = (byte) ((a << 2) | ((b >>> 4) & 3));
	    output[j++] = (byte) (((b & 15) << 4) | ((c >>> 2) & 15));
	    output[j++] = (byte) (((c & 3) << 6) | d);
	    l--;
	}
	if (k >= 2) {
	    a = code[i++];
	    b = code[i++];
	    output[j++] = (byte) ((a << 2) | ((b >>> 4) & 3));
	}
	if (k >= 3) {
	    c = code[i++];
	    output[j++] = (byte) (((b & 15) << 4) | ((c >>> 2) & 15));
	}
	return output;
    }

    /**
     * Encodes a byte array into a hexadecimal string representation.
     * 
     * @param b
     *                The input byte array.
     * @return The string with the hexadecimal representation.
     */
    public static String toHex(byte[] b) {
	StringBuffer buf;
	int i;

	buf = new StringBuffer(b.length * 2);

	for (i = 0; i < b.length; i++) {
	    buf.append(HEX.charAt((b[i] >> 4) & 15));
	    buf.append(HEX.charAt(b[i] & 15));
	}
	return buf.toString();
    }
}
