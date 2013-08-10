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

import java.io.UnsupportedEncodingException;

/*
 * Bloody linux-jdk1.4 dumps core, have to use jdk1.3
 */
// import java.nio.charset.*;
// import java.nio.*;
/**
 * This class represents an ASN.1 UTF 8 String as described in ITU-T
 * Recommendation X.680.
 * 
 * @author Volker Roth
 * @version "$Id: ASN1UTF8String.java,v 1.4 2004/08/09 07:51:39 flautens Exp $"
 */
public class ASN1UTF8String extends ASN1AbstractString {
    /**
     * Creates an instance.
     */
    public ASN1UTF8String() {
	super();
    }

    /**
     * Creates an instance with the given string value. No constraints can be
     * set yet so none are checked.
     * 
     * @param s
     *                The string value.
     */
    public ASN1UTF8String(String s) {
	super(s);
    }

    /**
     * Returns the tag of this class.
     * 
     * @return The tag.
     */
    public int getTag() {
	return ASN1.TAG_UTF8STRING;
    }

    protected void setString0(String s) {
	try {
	    convert(s);
	} catch (ASN1Exception e) {
	    throw new IllegalArgumentException(e.getMessage());
	}
	super.setString0(s);
    }

    /**
     * Converts the given byte array to a string. The byte array must be in
     * UTF-8 encoding.
     * 
     * @param b
     *                The byte array to convert.
     */
    public String convert(byte[] b) throws ASN1Exception {
	if (b == null) {
	    throw new NullPointerException("Cannot convert null array!");
	}

	try {
	    return new String(b, 0, b.length, "UTF8");
	} catch (UnsupportedEncodingException e) {
	    throw new ASN1Exception("no UTF8");
	}
    }

    /**
     * Converts the given string to a byte array. The byte array contains the
     * UTF-8 encoding of the given String.
     * 
     * @param s
     *                The string to convert.
     */
    public byte[] convert(String s) throws ASN1Exception {
	if (s == null) {
	    throw new NullPointerException("Cannot convert null string!");
	}

	try {
	    return s.getBytes("UTF8");
	} catch (UnsupportedEncodingException e) {
	    throw new ASN1Exception("no UTF8");
	}
    }

    /**
     * Returns the number of bytes required to store the converted string.
     * 
     * @param s
     *                The string.
     */
    public int convertedLength(String s) throws ASN1Exception {
	return convert(s).length;
    }

}
