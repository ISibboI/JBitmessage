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

import java.io.IOException;

import codec.asn1.ASN1Exception;
import codec.asn1.ASN1IA5String;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1SequenceOf;
import codec.asn1.ASN1Type;
import codec.asn1.Decoder;
import codec.x509.X509Extension;

/**
 * <pre>
 *  id-ce-extCertificatePolicies OBJECT IDENTIFIER ::= {id-ce 32}
 * 
 *  CertificatePoliciesSyntax ::= SEQUENCE SIZE (1..MAX) OF
 * 	 	policyInformation
 * 
 * 	PolicyInformation ::= SEQUENCE {
 * 		policyIdentifier CertPolicyId,
 * 		policyQualifier SEQUENCE SIZE (1..MAX) OF 
 * 			policyQualifierInfo OPTIONAL
 * 	}
 * 
 * 	CertPolicyId ::= OBJECT IDENTIFIER
 * 
 * 	PolicyQualifierInfo ::= SEQUENCE {
 * 		policyQualifierId	PolicyQualifierId,
 *      qualifier         	ANY DEFINED BY policyQualifierId 
 *  }
 * 
 *  PolicyQualifierId ::= OBJECT IDENTIFIER
 * 
 * 	id-ce OBJECT IDENTIFIER  ::=  {joint-iso-ccitt(2) ds(5) 29}
 * 
 * </pre>
 * 
 * @author mal
 */
public class CertificatePoliciesExtension extends X509Extension {

    protected ASN1ObjectIdentifier id_ce_extCertificatePolicies = new ASN1ObjectIdentifier(
	    "2.5.29.32");

    /**
     * policyQualifierIds for Internet policy qualifiers defined in RFC3280:
     * id-qt-cps OBJECT IDENTIFIER ::= { id-qt 1 }
     * 
     * ... The CPS Pointer qualifier contains a pointer to a Certification
     * Practice Statement (CPS) published by the CA. The pointer is in the form
     * of a URI. Processing requirements for this qualifier are a local matter.
     * No action is mandated by this specification regardless of the criticality
     * value asserted for the extension. ...
     */
    public static final ASN1ObjectIdentifier ID_QT_CPS = new ASN1ObjectIdentifier(
	    "1.3.6.1.5.5.7.2.1");

    /**
     * 
     * THIS Qualifier is currently not supported by this class!
     * 
     * policyQualifierIds for Internet policy qualifiers defined in RFC3280:
     * id-qt-unotice OBJECT IDENTIFIER ::= { id-qt 2 }
     * 
     * ... The user notice has two optional fields: the noticeRef field and the
     * explicitText field. The noticeRef field, if used, names an organization
     * and identifies, by number, a particular textual statement prepared by
     * that organization. For example, it might identify the organization
     * "CertsRUs" and notice number 1. In a typical implementation, the
     * application software will have a notice file containing the current set
     * of notices for CertsRUs; the application will extract the notice text
     * from the file and display it. Messages MAY be multilingual, allowing the
     * software to select the particular language message for its own
     * environment.
     * 
     * 
     * An explicitText field includes the textual statement directly in the
     * certificate. The explicitText field is a string with a maximum size of
     * 200 characters.
     * 
     * If both the noticeRef and explicitText options are included in the one
     * qualifier and if the application software can locate the notice text
     * indicated by the noticeRef option, then that text SHOULD be displayed;
     * otherwise, the explicitText string SHOULD be displayed. ...
     */
    public static final ASN1ObjectIdentifier ID_QT_UNOTICE = new ASN1ObjectIdentifier(
	    "1.3.6.1.5.5.7.2.2");

    protected ASN1SequenceOf certificatePoliciesSyntax = new ASN1SequenceOf(
	    ASN1Sequence.class);

    /**
     * Default constructor for CertificatePoliciesExtension.
     * 
     * @throws Exception
     */
    public CertificatePoliciesExtension() throws Exception {
	this(false);
    }

    /**
     * Constructor for CertificatePoliciesExtension.
     * 
     * @param crit
     *                Determines if extension is marked critical
     * @throws Exception
     */
    public CertificatePoliciesExtension(boolean crit) throws Exception {
	super();

	setCritical(crit);
	setOID(id_ce_extCertificatePolicies);

	setValue(certificatePoliciesSyntax);
    }

    /**
     * Constructor for CertificatePoliciesExtension.
     * 
     * @param ext
     * @throws ASN1Exception
     * @throws IOException
     */
    public CertificatePoliciesExtension(byte[] ext) throws ASN1Exception,
	    IOException {
	super(ext);
    }

    /**
     * Adds a PolicyInformationSet to the extension
     * 
     * @param policyIdentifier
     *                the OID of the policy to add
     * @param policyQualifiers
     *                ASN1SequenceOf containing the policyQualifiers
     */
    public void addPolicyInformation(ASN1ObjectIdentifier policyIdentifier,
	    ASN1SequenceOf policyQualifiers) throws Exception {

	ASN1Sequence _policyInformation = new ASN1Sequence();
	_policyInformation.add(policyIdentifier);

	if (policyQualifiers == null) {
	    ASN1SequenceOf _policyQualifiers = new ASN1SequenceOf(
		    ASN1Sequence.class);
	    _policyQualifiers.setOptional(true);
	    _policyInformation.add(_policyQualifiers);
	} else {
	    policyQualifiers.setOptional(false);
	    _policyInformation.add(policyQualifiers);
	}
	certificatePoliciesSyntax.add(_policyInformation);

	setValue(certificatePoliciesSyntax);
    }

    public void addPolicyInformation(ASN1ObjectIdentifier policyIdentifier)
	    throws Exception {
	addPolicyInformation(policyIdentifier, null);
    }

    /**
     * adds a PolicyInformation defined by an ID and the pointer to the
     * Certificate Practice Statement.
     * 
     * @param policyIdentifier
     *                OID of the Policy
     * @param locationOfCPS
     *                a URI pointing to the Trust Center's CPS
     */
    public void addPolicyInformationCPS(ASN1ObjectIdentifier policyIdentifier,
	    ASN1IA5String locationOfCPS) throws Exception {

	ASN1Sequence _policyInformation = new ASN1Sequence(2);
	_policyInformation.add(policyIdentifier);

	ASN1Sequence _policyQualifier = new ASN1Sequence(2);
	_policyQualifier.add(ID_QT_CPS.clone());
	_policyQualifier.add(locationOfCPS);
	_policyQualifier.setOptional(false);

	ASN1SequenceOf _policyQualifiers = new ASN1SequenceOf(
		ASN1Sequence.class);
	_policyQualifiers.add(_policyQualifier);
	_policyInformation.add(_policyQualifiers);

	certificatePoliciesSyntax.add(_policyInformation);
	setValue(certificatePoliciesSyntax);
    }

    public void decode(Decoder dec) throws ASN1Exception, IOException {

	super.decode(dec);

	ASN1Type inner = (ASN1Type) super.getValue();

	if (!(inner instanceof ASN1SequenceOf)) {
	    throw new ASN1Exception("unexpected type of inner value "
		    + inner.getClass().getName());
	}

	if (!(((ASN1SequenceOf) inner).getElementType()
		.equals(ASN1Sequence.class))) {
	    throw new ASN1Exception("unexpected content of inner type "
		    + ((ASN1SequenceOf) inner).getElementType().toString());
	}

	certificatePoliciesSyntax = (ASN1SequenceOf) inner;

    }

    public String toString(String offset) {
	int i;
	StringBuffer buf = new StringBuffer(offset
		+ "CertificatePoliciesExtension ["
		+ id_ce_extCertificatePolicies + "] {");

	if (isCritical()) {
	    buf.append(" (CRITICAL)\n");
	} else {
	    buf.append(" (NOT CRITICAL)\n");
	}

	for (i = 0; i < certificatePoliciesSyntax.size(); i++) {
	    buf.append(offset);
	    buf.append("Policy " + (i + 1) + ": ");
	    buf.append(certificatePoliciesSyntax.get(i).toString());
	    buf.append("\n");
	}
	buf.append(offset + "}\n");

	return buf.toString();
    }

}
