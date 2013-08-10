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
 * The ASN1NOP class helps to keep ASN1Types at fixed positions in the internal
 * list. The class realize the Null Object - Pattern . If an optional ASN1Type
 * is not present the ASN1NOP should used to fill its place. So all other
 * ASN1Types in this ASN1Sequence remains at the same position. This class will
 * be ignored while encoding. Other methods than getInstance() or isOptional()
 * will throw an UnsupportedOperationException.
 * 
 * @author Frank Lautenschläger Created on 23.07.2004
 */
public final class ASN1NOP implements ASN1Type {
    /**
     * singleton
     */
    private static final ASN1NOP INSTANCE = new ASN1NOP();

    /**
     * No-one can instantiate this class.
     */
    private ASN1NOP() {
    }

    /**
     * Returns the singleton
     * 
     * @return ASN1NOP - singleton instance
     */
    public static ASN1NOP getInstance() {
	return INSTANCE;
    }

    /**
     * DOCUMENT ME!
     * 
     * @return null
     * 
     * @throws UnsupportedOperationException
     * 
     * @see codec.asn1.ASN1Type#getValue()
     */
    public Object getValue() {
	throw new UnsupportedOperationException(
		"ASN1NOP is not a proper ASN1Type");
    }

    /**
     * The ASN1NOP always has the semantic of optional is true.
     * 
     * @param optional
     *                DOCUMENT ME!
     * 
     * @throws UnsupportedOperationException
     * 
     * @see codec.asn1.ASN1Type#setOptional(boolean)
     */
    public void setOptional(boolean optional) {
	throw new UnsupportedOperationException(
		"ASN1NOP is not a proper ASN1Type");
    }

    /**
     * The ASN1NOP always has the semantic of optional is true.
     * 
     * @see codec.asn1.ASN1Type#isOptional()
     */
    public boolean isOptional() {
	return true;
    }

    /**
     * DOCUMENT ME!
     * 
     * @return DOCUMENT ME!
     * 
     * @throws UnsupportedOperationException
     * 
     * @see codec.asn1.ASN1Type#getTag()
     */
    public int getTag() {
	throw new UnsupportedOperationException(
		"ASN1NOP is not a proper ASN1Type");
    }

    /**
     * (non-Javadoc)
     * 
     * @return DOCUMENT ME!
     * 
     * @throws UnsupportedOperationException
     * 
     * @see codec.asn1.ASN1Type#getTagClass()
     */
    public int getTagClass() {
	throw new UnsupportedOperationException(
		"ASN1NOP is not a proper ASN1Type");
    }

    /**
     * (non-Javadoc)
     * 
     * @param explicit
     *                DOCUMENT ME!
     * 
     * @throws UnsupportedOperationException
     * 
     * @see codec.asn1.ASN1Type#setExplicit(boolean)
     */
    public void setExplicit(boolean explicit) {
	throw new UnsupportedOperationException(
		"ASN1NOP is not a proper ASN1Type");
    }

    /**
     * (non-Javadoc)
     * 
     * @return DOCUMENT ME!
     * 
     * @throws UnsupportedOperationException
     * 
     * @see codec.asn1.ASN1Type#isExplicit()
     */
    public boolean isExplicit() {
	throw new UnsupportedOperationException(
		"ASN1NOP is not a proper ASN1Type");
	// return false;
    }

    /**
     * DOCUMENT ME!
     * 
     * @param tag
     *                DOCUMENT ME!
     * @param tagclass
     *                DOCUMENT ME!
     * 
     * @return DOCUMENT ME!
     * 
     * @throws UnsupportedOperationException
     * 
     * @see codec.asn1.ASN1Type#isType(int, int)
     */
    public boolean isType(int tag, int tagclass) {
	throw new UnsupportedOperationException(
		"ASN1NOP is not a proper ASN1Type");
    }

    /**
     * The encode method returns without writing anything to the encoder.
     * 
     * @param enc
     *                DOCUMENT ME!
     * @throws UnsupportedOperationException
     * 
     * @see codec.asn1.ASN1Type#encode(codec.asn1.Encoder)
     */
    public void encode(Encoder enc) {
	throw new UnsupportedOperationException(
		"ASN1NOP is not a proper ASN1Type");
    }

    /**
     * DOCUMENT ME!
     * 
     * @param dec
     *                DOCUMENT ME!
     * @throws UnsupportedOperationException
     * 
     * @see codec.asn1.ASN1Type#decode(codec.asn1.Decoder)
     */
    public void decode(Decoder dec) {
	throw new UnsupportedOperationException(
		"ASN1NOP should not be used for decoding at all");
    }

    /**
     * ASN1NOP needs no constraints
     * 
     * @param o
     *                DOCUMENT ME!
     * 
     * @throws UnsupportedOperationException
     * 
     * @see codec.asn1.ASN1Type#setConstraint(codec.asn1.Constraint)
     */
    public void setConstraint(Constraint o) {
	throw new UnsupportedOperationException(
		"ASN1NOP is not a proper ASN1Type");
    }

    /**
     * ASN1NOP has no constraints
     * 
     * @see codec.asn1.ASN1Type#getConstraint()
     */
    public Constraint getConstraint() {
	throw new UnsupportedOperationException(
		"ASN1NOP is not a proper ASN1Type");
    }

    /**
     * DOCUMENT ME!
     * 
     * @throws UnsupportedOperationException
     * 
     * @see codec.asn1.ASN1Type#checkConstraints()
     */
    public void checkConstraints() {
	throw new UnsupportedOperationException(
		"ASN1NOP is not a proper ASN1Type");
    }
}
