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
package codec.pkcs9;

import java.util.Iterator;

import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1SetOf;
import codec.asn1.ASN1Type;
import codec.asn1.OIDRegistry;
import codec.pkcs.PKCSRegistry;
import codec.x501.Attribute;

/**
 * This class represents <code>Attributes</code> as defined in PKCS#6. The
 * ASN.1 definition of this structure is
 * <p>
 * <blockquote>
 * 
 * <pre>
 * Attributes ::= SET OF Attribute
 * </pre>
 * 
 * </blockquote>
 * 
 * Instances can be initialized with a {@link OIDRegistry OIDRegistry} that is
 * used to resolve attribute value types. The type of value of a PKCS#6 Content
 * Type Attribute is for instance <code>OBJECT IDENTIFIER</code>. The OID of
 * this attribute is <code>{ pkcs-9 3}</code>. The OID identifies both the
 * attribute and the attribute value's type.
 * <p>
 * 
 * Please note that when a registry is specified, exceptions are thrown if an
 * attribute is encountered whose type cannot be resolved by that registry or
 * any of the global registries.
 * 
 * @author Volker Roth
 * @version "$Id: Attributes.java,v 1.2 2000/12/06 17:47:33 vroth Exp $"
 */
public class Attributes extends ASN1SetOf {
    /**
     * The registry that is used to resolve attribute values.
     */
    protected OIDRegistry registry_;

    /**
     * Creates an instance ready for parsing. Any type of attribute is accepted.
     */
    public Attributes() {
	super(0);
    }

    /**
     * Creates an instance ready for parsing. The given
     * {@link OIDRegistry OIDRegistry} is used to resolve the attribute value
     * types. Attributes that cannot be resolved will cause exceptions upon
     * decoding.
     * 
     * @param registry
     *                The <code>OIDRegistry</code> to use for resolving
     *                attribute value types, or <code>
     *   null</code> if the
     *                default PKCS registry shall be used.
     */
    public Attributes(OIDRegistry registry) {
	super(0);

	if (registry == null) {
	    registry_ = PKCSRegistry.getDefaultRegistry();
	    return;
	}
	registry_ = registry;
    }

    /**
     * Returns the first attribute of the given type that is found in this
     * instance.
     * 
     * @param oid
     *                The type of the attribute.
     * @return The attribute with the given OID or <code>null
     *   </code> if no
     *         matching attribute is found.
     */
    public Attribute getAttribute(ASN1ObjectIdentifier oid) {
	if (oid == null) {
	    throw new NullPointerException("Need an OID!");
	}
	Attribute attribute;
	Iterator i;

	for (i = iterator(); i.hasNext();) {
	    attribute = (Attribute) i.next();
	    if (attribute.getOID().equals(oid))
		return attribute;
	}
	return null;
    }

    /**
     * Returns <code>true</code> if an attribute of the given type exists in
     * this instance. This method calls <code>
     * getAttribute(ASN1ObjectIdentifier)</code>.
     * Do not use it if you want to retrieve the attribute subsequent to this
     * method call anyway.
     * 
     * @param oid
     *                The type of the attribute.
     * @return <code>true</code> if an attribute with the given OID exists.
     */
    public boolean containsAttribute(ASN1ObjectIdentifier oid) {
	return (getAttribute(oid) != null);
    }

    /**
     * Returns the attribute at the given position.
     * 
     * @param index
     *                The position of the attribute to return.
     * @throws ArrayIndexOutOfBoundsException
     *                 if the given index is not within the bounds of the
     *                 attributes list.
     */
    public Attribute getAttribute(int index) {
	return (Attribute) get(index);
    }

    /**
     * Returns <code>Attribute.class</code>.
     * 
     * @return <code>Attribute.class</code>
     */
    public Class getElementType() {
	return Attribute.class;
    }

    /**
     * Returns a new attribute instance. The new attribute is added to this
     * instance automatically.
     * 
     * @return The new attribute, ready to be decoded.
     */
    public ASN1Type newElement() {
	Attribute attribute;

	if (registry_ == null) {
	    attribute = new Attribute();
	} else {
	    attribute = new Attribute(registry_);
	}
	add(attribute);

	return attribute;
    }
}
