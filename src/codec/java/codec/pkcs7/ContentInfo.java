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
package codec.pkcs7;

import java.io.IOException;

import codec.asn1.ASN1Exception;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1OpenType;
import codec.asn1.ASN1RegisteredType;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1TaggedType;
import codec.asn1.ASN1Type;
import codec.asn1.Decoder;
import codec.asn1.OIDRegistry;
import codec.pkcs.PKCSRegistry;

/**
 * This class represents a <code>ContentInfo</code> as defined in <a
 * href="http://www.rsa.com/rsalabs/pubs/PKCS/html/pkcs-7.html"> PKCS#7</a>.
 * The ASN.1 definition of this structure is
 * <p>
 * 
 * <pre>
 * ContentInfo ::= SEQUENCE {
 *   contentType ContentType,
 *   content [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL
 * }
 * ContentType ::= OBJECT IDENTIFIER
 * </pre>
 * 
 * <p>
 * <code>contentType</code> indicates the type of content. PKCS#7 specifies
 * six content types, of which five are supported: {@link Data data},
 * {@link SignedData signedData}, {@link EnvelopedData envelopedData},
 * {@link SignedAndEnvelopedData signedAndEnvelopedData}, and
 * {@link EncryptedData encryptedData}. All of these content types have
 * registered OIDs.
 * <p>
 * 
 * The <code>ContentInfo</code> is also the general syntax of a complete
 * PKCS#7 structure.
 * <p>
 * 
 * @author Volker Roth
 * @version "$Id: ContentInfo.java,v 1.4 2000/12/07 13:21:52 vroth Exp $"
 */
public class ContentInfo extends ASN1Sequence {

    /**
     * The OID defining the contents of this structure.
     */
    protected ASN1ObjectIdentifier contentType_;

    /**
     * The actual content of this structure.
     */
    protected ASN1TaggedType content_;

    /**
     * This method creates an instance which is initialized for parsing. The
     * {@link PKCSRegistry PKCSRegistry} is used for resolving OIDs to PKCS7
     * structures.
     */
    public ContentInfo() {
	this(PKCSRegistry.getDefaultRegistry());
    }

    /**
     * Creates an instance ready for decoding. The given
     * <code>OIDRegistry</code> is used to resolve content types. By default
     * the {@link PKCSRegistry PKCSRegistry} is used.
     * 
     * @param registry
     *                The Object Identifier registry that is used to resolve
     *                content types, or <code>null
     *   </code> if a default
     *                registry shall be used.
     */
    public ContentInfo(OIDRegistry registry) {
	super(2);

	ASN1OpenType ot;

	if (registry == null) {
	    registry = PKCSRegistry.getDefaultRegistry();
	}
	contentType_ = new ASN1ObjectIdentifier();
	ot = new ASN1OpenType(registry, contentType_);
	content_ = new ASN1TaggedType(0, ot, true, true);

	add(contentType_);
	add(content_);
    }

    /**
     * This constructor sets the content type to the given OID but leaves the
     * actual content empty. This is a constructor required for instance by the
     * {@link SignedData SignedData} type in the case of signing detached
     * signatures. Such signatures require the content type to be
     * {@link Data Data}, but the actual data must be empty (no identifier,
     * length and contents octets).
     * <p>
     * 
     * This method calls {link #setContent(codec.asn1,ASN1ObjectIdentifier)
     * setContent(oid)}.
     * 
     * @param o
     *                The OID denoting the content type, most probably the
     *                {@link Data Data} content OID.
     */
    public ContentInfo(ASN1ObjectIdentifier o) {
	super(1);
	setContent(o);
    }

    /**
     * This method calls {@link #setContent(ASN1RegisteredType) setContent} with
     * the given ASN.1 type, which builds the tree of ASN.1 objects used for
     * decoding this structure.
     * 
     * @param o
     *                The PKCS#7 content type to embed in this structure.
     */
    public ContentInfo(ASN1RegisteredType o) {
	super(2);
	setContent(o);
    }

    /**
     * Returns the <code>contentType</code> of this structure. This value is
     * defined only if the structure has been decoded successfully, or the
     * content has been set previously.
     * 
     * @return The OID describing the <code>contentType</code> of this
     *         structure.
     */
    public ASN1ObjectIdentifier getContentType() {
	return contentType_;
    }

    /**
     * This method returns the actual <code>content</code> of this structure.
     * 
     * @return The <code>content</code> or <code>null</code> if no content
     *         is available.
     */
    public ASN1Type getContent() {
	ASN1Type o;

	if (content_.isOptional()) {
	    return null;
	}
	o = content_.getInnerType();

	if (o instanceof ASN1OpenType) {
	    return null;
	}
	return o;
    }

    /**
     * Sets the content type to the given OID and clears the actual content. The
     * OID is copied by reference. Modifying it afterwards causes side effects.
     * 
     * @param oid
     *                The OID that identifies the (empty) content type.
     */
    public void setContent(ASN1ObjectIdentifier oid) {
	clear();

	contentType_ = oid;
	content_ = null;

	add(contentType_);
    }

    /**
     * This method sets the content of this structure. This method calls {@link
     * #setContent(codec.asn1.ASN1ObjectIdentifier,codec.asn1.ASN1Type)
     * setContent(ASN1ObjectIdentifier, ASN1Type)} with the OID returned by
     * {@link ASN1RegisteredType#getOID ASN1RegisteredType.getOID()}.
     * 
     * @param type
     *                The content that shall be set.
     */
    public void setContent(ASN1RegisteredType type) {
	setContent(type.getOID(), type);
    }

    /**
     * This method sets the OID and content of this structure. The OID is cloned
     * and the type is stored by reference. Subsequent modification of the type
     * has side effects.
     * 
     * @param oid
     *                The OID that identifies the content type.
     * @param type
     *                The content.
     */
    public void setContent(ASN1ObjectIdentifier oid, ASN1Type type) {
	clear();

	contentType_ = (ASN1ObjectIdentifier) oid.clone();
	content_ = new ASN1TaggedType(0, type, true);

	add(contentType_);
	add(content_);
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

	if (!content_.isOptional()) {
	    t = content_.getInnerType();

	    if (t instanceof ASN1OpenType) {
		o = (ASN1OpenType) t;
		content_.setInnerType(o.getInnerType());
	    }
	}
    }

}
