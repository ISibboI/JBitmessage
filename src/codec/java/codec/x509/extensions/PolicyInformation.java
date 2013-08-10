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
package codec.x509.extensions;

import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1Opaque;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1SequenceOf;

/**
 * <pre>
 * 	PolicyInformation ::= SEQUENCE {
 * 		policyIdentifier CertPolicyId,
 * 		policyQualifiers SEQUENCE SIZE (1..MAX) OF 
 * 		             PolicyQualifierInfo OPTIONAL
 * 	}
 * 
 * </pre>
 * 
 * According to profile, this is used without addional PolicyQualifierInfo.
 * 
 * <pre>
 * 	CertPolicyId ::= OBJECT IDENTIFIER
 * 
 * 	PolicyQualifierInfo ::= SEQUENCE {
 * 	   policyQualifierId	PolicyQualifierId,
 *         qualifier         	ANY DEFINED BY policyQualifierId 
 *  }
 * 
 *  PolicyQualifierId ::= OBJECT IDENTIFIER
 * 
 * 	id-ce OBJECT IDENTIFIER  ::=  {joint-iso-ccitt(2) ds(5) 29}
 * 
 * </pre>
 * 
 * @author Volker Roth
 * @version "$Id: PolicyInformation.java,v 1.1 2004/08/16 13:31:38 pebinger Exp $"
 */
public class PolicyInformation extends ASN1Sequence {
    private ASN1ObjectIdentifier policyIdentifier_;
    private ASN1Sequence policyQualifiers_;

    /**
     * Initializes an instance for decoding.
     */
    public PolicyInformation() {
	super(2);

	policyIdentifier_ = new ASN1ObjectIdentifier();

	/*
	 * According to the profile, no PolicyQualifierInfo is ever used. Hence,
	 * we do not bother about any contents. The opaque object just reads
	 * whatever is there (if there is something) without actually decoding
	 * the PolicyQualifierInfo. Furthermore, it is OPTIONAL. Hence, we
	 * generally omit it.
	 */
	policyQualifiers_ = new ASN1SequenceOf(ASN1Opaque.class);
	policyQualifiers_.setOptional(true);

	add(policyIdentifier_);
	add(policyQualifiers_);
    }

    /**
     * Initializes an instance for encoding with the given value.
     * 
     * @param policyIdentifier
     *                The policyIdentifier OID. This value is copied into this
     *                structure by reference. Beware of side effects.
     */
    public PolicyInformation(ASN1ObjectIdentifier policyIdentifier) {
	super(1);

	if (policyIdentifier == null) {
	    throw new NullPointerException("policyIdentifier");
	}
	policyIdentifier_ = policyIdentifier;

	add(policyIdentifier_);
    }

    /**
     * Initializes an instance for encoding with the given values.
     * 
     * @param policyIdentifier
     *                The policyIdentifier OID. This value is copied into this
     *                structure by reference. Beware of side effects.
     * @param policyQualifiers
     *                The <code>ASN1Sequence</code> with the policyQualifier
     *                structure. This parameter is copied by reference. Beware
     *                of side effects. The correctness of this parameter is not
     *                verified.
     */
    public PolicyInformation(ASN1ObjectIdentifier policyIdentifier,
	    ASN1Sequence policyQualifiers) {
	super(2);

	if (policyIdentifier == null) {
	    throw new NullPointerException("policyIdentifier");
	}
	policyIdentifier_ = policyIdentifier;
	add(policyIdentifier_);

	/*
	 * If no qualifiers are given then we add none.
	 */
	if (policyQualifiers == null || policyQualifiers.size() == 0) {
	    return;
	}
	policyQualifiers_ = policyQualifiers;
	add(policyQualifiers_);
    }

    public ASN1ObjectIdentifier getPolicyIdentifier() {
	return policyIdentifier_;
    }

    /**
     * @return The PolicyQualifiers or <code>null</code> if none is contained
     *         in this structure.
     */
    public ASN1Sequence getPolicyQualifiers() {
	if (policyQualifiers_ == null || policyQualifiers_.isOptional()) {
	    return null;
	}
	return policyQualifiers_;
    }

}
