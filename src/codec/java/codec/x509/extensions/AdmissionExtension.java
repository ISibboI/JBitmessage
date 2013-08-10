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
import java.security.cert.CertificateEncodingException;

import codec.asn1.ASN1Exception;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1SequenceOf;
import codec.asn1.ConstraintException;
import codec.asn1.Decoder;
import codec.x509.GeneralName;
import codec.x509.X509Extension;

/**
 * Class (in combination with other classes) implements the Admission Extension
 * of the ISIS MTT SigG_Core_Spec_V_1_0_2.
 * 
 * id-isismtt-at-admission OBJECT IDENTIFIER ::= {id-isismtt-at 3}
 * id-isismtt-at-namingAuthorities OBJECT IDENTIFIER ::= {id-isismtt-at 11}
 * 
 * AdmissionSyntax ::= SEQUENCE { admissionAuthority GeneralName OPTIONAL,
 * contentsOfAdmissions SEQUENCE OF Admissions }
 * 
 * Admissions ::= SEQUENCE { admissionAuthority [0] EXPLICIT GeneralName
 * OPTIONAL, namingAuthority [1] EXPLICIT NamingAuthority OPTIONAL,
 * professionInfos SEQUENCE OF ProfessionInfo }
 * 
 * NamingAuthority ::= SEQUENCE { namingAuthorityId OBJECT IDENTIFIER OPTIONAL,
 * namingAuthorityUrl IA5String OPTIONAL, namingAuthorityText
 * DirectoryString(SIZE(1..128)) OPTIONAL}
 * 
 * ProfessionInfo ::= SEQUENCE { namingAuthority [0] EXPLICIT NamingAuthority
 * OPTIONAL, professionItems SEQUENCE OF DirectoryString (SIZE(1..128)),
 * professionOIDs SEQUENCE OF OBJECT IDENTIFIER OPTIONAL, registrationNumber
 * PrintableString(SIZE(1..128)) OPTIONAL, addProfessionInfo OCTET STRING
 * OPTIONAL }
 * 
 * @author Christian Valentin
 */
public class AdmissionExtension extends X509Extension

{

    /**
     * Generalname of the first Admissionauthority
     */
    private GeneralName admissionAuthority = null;

    /**
     * holds the Admissions, at least one, up to many.
     */
    private ASN1Sequence admissions = new ASN1SequenceOf(Admissions.class);

    /**
     * OID : id-isismtt-at 3
     */
    public static final String EXTENSION_OID = "1.3.36.8.3.3";

    /**
     * Sequence containing the AdmissionSyntax
     */
    private ASN1Sequence admissionSyntax = null;

    /**
     * constructor, using the Generalname of the first Admissionauthority as
     * Parameter.
     */
    public AdmissionExtension(GeneralName adAuth) {

	admissionSyntax = new ASN1Sequence();
	admissionAuthority = adAuth;
	setCritical(false);
	try {
	    setOID(new ASN1ObjectIdentifier(EXTENSION_OID));
	    admissionSyntax.add(admissionAuthority);
	    setValue(admissionSyntax);
	} catch (ConstraintException ce) {
	    ce.printStackTrace();
	} catch (CertificateEncodingException cee) {
	    cee.printStackTrace();
	}
    }

    /**
     * constructor, using an Admission as Parameter
     */
    public AdmissionExtension(ASN1Sequence ad) {
	admissionSyntax = new ASN1Sequence();
	setCritical(false);

	admissions = ad;
	admissionSyntax.add(admissions);

	try {
	    setOID(new ASN1ObjectIdentifier(EXTENSION_OID));
	    setValue(admissionSyntax);
	} catch (ConstraintException ce) {
	    ce.printStackTrace();
	} catch (CertificateEncodingException cee) {
	    cee.printStackTrace();
	}
    }

    /**
     * adds the Sequence holding the Admissions to the extension
     */
    public void addAdmission(ASN1Sequence admissions_) {
	admissions = admissions_;
	admissionSyntax.add(admissions);
	try {
	    setValue(admissionSyntax);
	} catch (CertificateEncodingException cee) {
	    cee.printStackTrace();
	}
    }

    public void decode(Decoder dec) throws ASN1Exception, IOException {
	super.decode(dec);
	super.decodeExtensionValue(admissionAuthority);
	super.decodeExtensionValue(admissions);
    }

    public String toString() {
	String result;

	result = "Extension OID : " + EXTENSION_OID;

	if (this.admissionAuthority != null) {
	    result = result + "\n" + this.admissionAuthority;
	}
	result = result + "\n" + this.admissionSyntax;
	return result;
    }

}
