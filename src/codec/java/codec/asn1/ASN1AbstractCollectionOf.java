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

import java.io.IOException;

/**
 * Represents the ASN.1 SEQUENCE OF and SET OF types in a general way.
 * 
 * @author Volker Roth
 * @version "$Id: ASN1AbstractCollectionOf.java,v 1.2 2005/03/22 16:21:17
 *          flautens Exp $"
 */
public abstract class ASN1AbstractCollectionOf extends ASN1AbstractCollection
	implements ASN1CollectionOf {
    /**
     * The class contained by this ASN1AbstractCollectionOf
     */
    private Class type_;

    /**
     * Creates an instance with the given capacity.
     * 
     * @param capacity
     *                The capacity.
     * @param type
     *                The class managed by this ASN1AbstractCollectionOf
     */
    public ASN1AbstractCollectionOf(int capacity, Class type) {
	super(capacity);

	if (type == null) {
	    throw new NullPointerException("Need a class!");
	}

	if (!ASN1Type.class.isAssignableFrom(type)) {
	    throw new IllegalArgumentException("Class is not an ASN1Type!");
	}

	type_ = type;
    }

    /**
     * Creates an instance
     * 
     * @param type
     *                The class managed by this ASN1AbstractCollectionOf
     */
    public ASN1AbstractCollectionOf(Class type) {
	super();

	if (type == null) {
	    throw new NullPointerException("Need a class!");
	}

	if (!ASN1Type.class.isAssignableFrom(type)) {
	    throw new IllegalArgumentException("Class is not an ASN1Type!");
	}

	type_ = type;
    }

    /**
     * Reads this collection from the given {@link Decoder Decoder}. This type
     * is initialized with the decoded data. The components of the decoded
     * collection must match the components of this collection. If they do then
     * the components are also initialized with the decoded values. Otherwise an
     * exception is thrown.
     * 
     * @param dec
     *                The decoder to read from.
     */
    public void decode(Decoder dec) throws ASN1Exception, IOException {
	dec.readCollectionOf(this);
	checkConstraints();
    }

    /**
     * Returns the Java class representing the ASN.1 type of the elements in
     * this collection.
     * 
     * @return The ASN.1 type of the elements in this collection.
     */
    public Class getElementType() {
	return type_;
    }

    /**
     * Abstract method declarations.
     * 
     * @return corresponding ASN1 tag
     */
    public abstract int getTag();
}
