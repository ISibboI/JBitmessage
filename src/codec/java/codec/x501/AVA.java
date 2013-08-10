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
package codec.x501;

import codec.Hex;

/**
 * This class encapsulates the key and value of a parsed
 * AttributeValueAssertions (AVA), and indicates whether an AVA has a
 * continuation at the same level (a multi valued RDN). This is not an ASN.1
 * object, do not add it to e.g., an <code>ASN1Sequence</code>.
 * 
 * @author Volker Roth
 * @author Jan Peters
 * @version "$Id: AVA.java,v 1.2 2007/08/30 08:45:05 pebinger Exp $"
 * @see RFC2253Parser
 * @see Name
 */
public class AVA extends Object {
    /**
     * The attribute key of the AVA.
     */
    private String key_;

    /**
     * The string value of the AVA, if given.
     */
    private String val_;

    /**
     * The encoded value of the AVA, if given.
     */
    private byte[] buf_;

    /**
     * Flag indicating, whether the AVA has a continuation at the same level.
     */
    private boolean sib_;

    /**
     * Creates an instance.
     * 
     * @param key
     *                The attribute key.
     * @param value
     *                The attribute value.
     * @param hasSibling
     *                <code>true</code> iff this AVA is followed by another
     *                AVA at the same level. In other words, a value of true
     *                signals that this AVA is one in a sequence of AVAs of a
     *                multi valued RDN.
     */
    public AVA(String key, String value, boolean hasSibling) {
	key_ = key;
	val_ = value;
	sib_ = hasSibling;
    }

    /**
     * Creates an instance with a DER encoded value.
     * 
     * @param key
     *                The attribute key.
     * @param buf
     *                The encoded attribute value.
     * @param hasSibling
     *                <code>true</code> iff this AVA is followed by another
     *                AVA at the same level. In other words, a value of true
     *                signals that this AVA is one in a sequence of AVAs of a
     *                multi valued RDN.
     */
    public AVA(String key, byte[] buf, boolean hasSibling) {
	key_ = key;
	buf_ = buf;
	sib_ = hasSibling;
    }

    /**
     * Returns the attribute key of the AVA
     * 
     * @return The attribute key of the AVA
     */
    public String getKey() {
	return key_;
    }

    /**
     * Returns the string value of the AVA. If only an encoded value is given,
     * this value is transformed first.
     * 
     * @return the string value of the AVA.
     */
    public String getValue() {
	if (val_ == null && isEncodedValue()) {
	    val_ = Hex.encode(buf_);
	}
	return val_;
    }

    /**
     * @return <code>true</code> if this AVA is followed by another one that
     *         was separated from this one by means of a plus sign. In other
     *         words, this AVA and the next belong to the same RDN.
     */
    public boolean hasSibling() {
	return sib_;
    }

    /**
     * Returns the status of the attribute value.
     * 
     * @return <code>true</code> if the attribute value is a byte array.
     */
    public boolean isEncodedValue() {
	return (buf_ != null);
    }

    /**
     * Returns the encoded value of the AVA, if given.
     * 
     * @return the encoded value of the AVA.
     */
    public byte[] getEncodedValue() {
	return buf_;
    }

    /**
     * Returns the string representation of the AVA.
     * 
     * @return the string representation of the AVA.
     */
    public String toString() {
	String output = key_ + "=";

	if (isEncodedValue()) {
	    output += "#";
	}
	output += getValue();
	return output;
    }

    /**
     * Indicates whether some other object is "equal to" this one.
     * 
     * @param o
     *                the reference object with which to compare.
     * @return <code>true</code> if this object is the same as the given
     *         object; <code>false</code> otherwise.
     */
    public boolean equals(Object o) {
	AVA entry;

	if (o == null) {
	    return false;
	}

	if (!(o instanceof AVA)) {
	    return false;
	}
	entry = (AVA) o;

	if (getKey().equals(entry.getKey())) {
	    if (getValue().equals(entry.getValue())) {
		return true;
	    }
	}
	return false;
    }
}
