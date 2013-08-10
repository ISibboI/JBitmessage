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
package codec.asn1;

/**
 * Represents a UniversalString. This string type uses a 4-octet encoding of
 * characters. For more details on strings see
 * {@link ASN1AbstractString ASN1AbstractString}.
 * 
 * @author Volker Roth
 * @version "$Id: ASN1UniversalString.java,v 1.2 2000/12/06 17:47:27 vroth Exp $"
 * @see ASN1AbstractString
 */
public class ASN1UniversalString extends ASN1AbstractString {

    public ASN1UniversalString() {
	super();
    }

    /**
     * Creates an instance with the given string value. No constraints could be
     * set yet so none are checked.
     * 
     * @param s
     *                The string value.
     */
    public ASN1UniversalString(String s) {
	super(s);
    }

    /**
     * Returns the ASN.1 {@link ASN1#TAG_UNIVERSALSTRING tag} of this type.
     * 
     * @return The tag value.
     */
    public int getTag() {
	return ASN1.TAG_UNIVERSALSTRING;
    }

    /**
     * Converts the given byte array to a string by reading four bytes per
     * character from the array and concatenating them into a Unicode character.
     * 
     * @param b
     *                The byte array to convert.
     */
    public String convert(byte[] b) throws ASN1Exception {
	if (b == null)
	    throw new NullPointerException("Cannot convert null array!");

	if ((b.length % 4) != 0)
	    throw new ConstraintException("Truncated character encoding!");

	char[] c = new char[b.length / 4];
	for (int j = 0, i = 0; i < c.length; i++, j += 4)
	    c[i] = (char) (((b[j] << 24) & 0xff000000)
		    | ((b[j + 1] << 16) & 0xff0000)
		    | ((b[j + 2] << 8) & 0xff00) | (b[j + 3] & 0xff));

	return String.valueOf(c);
    }

    /**
     * Converts the given string to a byte array where each character is
     * transformed into 4 consecutive bytes.
     * 
     * @param s
     *                The string to convert.
     */
    public byte[] convert(String s) {
	if (s == null)
	    throw new NullPointerException("Cannot convert null string!");

	char[] c = s.toCharArray();
	byte[] b = new byte[c.length * 4];

	for (int i = 0, j = 0; i < c.length; i++) {
	    b[j++] = (byte) ((c[i] >>> 24) & 0xff);
	    b[j++] = (byte) ((c[i] >>> 16) & 0xff);
	    b[j++] = (byte) ((c[i] >>> 8) & 0xff);
	    b[j++] = (byte) (c[i] & 0xff);
	}
	return b;
    }

    /**
     * Returns the number of bytes required to store the converted string.
     * 
     * @param s
     *                The string.
     * 
     */
    public int convertedLength(String s) {
	return s.length() * 4;

    }
}
