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
package codec.pkcs12;

import java.io.IOException;

import codec.asn1.ASN1Exception;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1OpenType;
import codec.asn1.ASN1RegisteredType;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1SetOf;
import codec.asn1.ASN1TaggedType;
import codec.asn1.ASN1Type;
import codec.asn1.Decoder;
import codec.x501.Attribute;

/**
 * This class represents a <code>SafeBag</code> as defined in <a
 * href="http://www.rsasecurity.com/rsalabs/pkcs/pkcs-12/index.html"> PKCS#12</a>.
 * The ASN.1 definition of this structure is
 * <p>
 * 
 * <pre>
 * SafeBag  ::= SEQUENCE {
 *   bagId           BAG-TYPE.&amp;id ({PKCS12BagSet}),
 *   bagValue        [0] EXPLICIT BAG-TYPE.&amp;Type ({PKCS12BagSet}{&#0064;bagId})
 *   bagAttributes   SET OF PKCS12Attribute OPTIONAL
 * }
 * 
 * PKCS12Attribute::=SEQUENCE {
 *   attrId          Attribute.&amp;id ({PKCS12AttrSet}),
 *   attrValues      SET OF ATTRIBUTE.&amp;Type ({PKCS12AttrSet}{&#0064;attrId}) -- this type is compatible with the x.500 type 'Attribute'
 * 
 * PKCS12AttrSet ATTRIBUTE::={
 *        friendlyName| -- from PKCS#9
 *        localKeyId,   -- from PKCS#9
 *        ...           -- Other Attributes allowed
 * 
 * This class is sonly used for resolving pkcs12 PDUs. To construct a 
 * PFXpdu please construct a SafeContents from one of the bag types directly.
 * Supported bagtypes are{@link KeyBag keyBag}, 
 * {@link PKCS8ShroudedKeyBag pkcs8ShroudedKeyBag}, {@link CertBag certBag}, 
 * {@link CRLBag crlBag}, {@link SecretBag secretBag}, 
 * {@link SafeContents safeContents}.  
 * </pre>
 * 
 * <p>
 * 
 * @author Michele Boivin
 * @version "$Id: SafeBag.java,v 1.3 2003/01/28 04:46:06 jpeters Exp $"
 */
public class SafeBag extends ASN1Sequence implements java.io.Serializable {

    /**
     * The OID defining the bagId.
     */
    private ASN1ObjectIdentifier bagId_;

    /**
     * 
     */
    private ASN1TaggedType bagValue_;

    /**
     * bagAttributes.
     */
    private ASN1SetOf bagAttributes_;

    /**
     * The OID Registry for resolving
     */
    protected PKCS12OIDRegistry reg_ = new PKCS12OIDRegistry();

    /**
     * Default constructor.
     */
    public SafeBag() {
	super(3);

	bagId_ = new ASN1ObjectIdentifier();
	add(bagId_);

	ASN1OpenType ot = new ASN1OpenType(reg_, bagId_);
	bagValue_ = new ASN1TaggedType(0, ot, true);
	add(bagValue_);

	bagAttributes_ = new ASN1SetOf(Attribute.class);
	bagAttributes_.setOptional(true);
	add(bagAttributes_);
    }

    /**
     * Decodes this instance. This method extracts the actual content type from
     * the {@link ASN1OpenType ASN1OpenType}.
     * 
     * @param decoder
     *                The {@link Decoder Decoder} to use.
     */
    public void decode(Decoder decoder) throws ASN1Exception, IOException {
	super.decode(decoder);

	ASN1Type t;
	ASN1OpenType o;

	t = bagValue_.getInnerType();
	if (t instanceof ASN1OpenType) {
	    o = (ASN1OpenType) t;
	    bagValue_.setInnerType(o.getInnerType());
	}

    }

    public ASN1Type[] getAttributes() {
	return (ASN1Type[]) bagAttributes_.toArray();
    }

    /**
     * Returns the OID defining the type of this SafeBag
     * 
     * @return the OID defining the type of this SafeBag.
     */
    public ASN1ObjectIdentifier getBagType() {
	return bagId_;
    }

    /**
     * Returns the actual bag in the SafeBag.
     * 
     * @return the actual bag in the SafeBag.
     */
    public ASN1Type getBagValue() {
	return bagValue_.getInnerType();
    }

    /**
     * Sets this SafeBag's attributes
     * 
     * @param attr
     *                an array of attributes to be set
     */
    public void setAttributes(Attribute[] attr) {
	if (attr != null && attr.length > 0) {
	    bagAttributes_ = new ASN1SetOf(Attribute.class);
	    for (int i = 0; i < attr.length; i++)
		bagAttributes_.add(attr[i]);
	    add(bagAttributes_);
	}
    }

    /**
     * Sets the SafeBag's contents.
     * 
     * @param oid
     *                the OID describing the content type
     * @param bag
     *                the content itself
     */
    public void setBagContents(ASN1ObjectIdentifier oid, ASN1Type bag) {
	clear();
	bagId_ = (ASN1ObjectIdentifier) oid.clone();
	bagValue_ = new ASN1TaggedType(0, bag, true);
	add(bagId_);
	add(bagValue_);
    }

    /**
     * Sets the SafeBag's contents as a RegisteredType
     * 
     * @param bag
     *                the content as a RegisteredType
     */
    public void setBagContents(ASN1RegisteredType bag) {
	setBagContents(bag.getOID(), bag);
    }
}
