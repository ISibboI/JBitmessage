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

import java.security.cert.CertificateEncodingException;

import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1String;
import codec.asn1.ASN1Type;
import codec.x509.X509Extension;

/**
 * @author cval ValidityModel::= SEQUENCE { validityModelId OBJECT IDENTIFIER
 *         validityModelInfo ANY DEFINED BY validityModelId OPTIONAL }
 */

public class ValidityModelExtension extends X509Extension {
    public static final String EXTENSION_OID = "1.3.6.1.4.1.8301.3.5";

    private ASN1ObjectIdentifier oid_;

    private ASN1Type info_;

    protected ASN1Sequence validityModelSyntax;

    /**
     * Constructor
     */
    public ValidityModelExtension() throws Exception {
	// set parameters
	setOID(new ASN1ObjectIdentifier(EXTENSION_OID));
	setCritical(false);
	oid_ = new ASN1ObjectIdentifier("1.3.6.1.4.1.8301.3.5.1");

	// info_ = new ASN1OpenType();
	info_ = new codec.asn1.ASN1Null();
	info_.setOptional(true);

	validityModelSyntax = new ASN1Sequence();
	validityModelSyntax.add(oid_);
	validityModelSyntax.add(info_);

	setValue(validityModelSyntax);
    }

    public void setModelOid(ASN1ObjectIdentifier oid)
	    throws CertificateEncodingException {
	this.oid_ = oid;
	setValue(validityModelSyntax);
    }

    public void setModelInfo(ASN1String info)
	    throws CertificateEncodingException {
	this.info_ = info;
	validityModelSyntax.add(info_);
	setValue(validityModelSyntax);
    }

    /**
     * generates a human readable representation of the object. the
     * representation is indeted using the String offset, if possible.
     * 
     * @param offset
     *                String
     */
    public String toString(String offset) {
	StringBuffer buf = new StringBuffer(offset + "AuthorityInfoAccess ["
		+ getOID() + "] {");

	if (isCritical()) {
	    buf.append(" (CRITICAL)\n");
	} else {
	    buf.append(" (NOT CRITICAL)\n");
	}
	buf.append(offset + oid_.toString());
	buf.append(offset + "}\n");
	if (!info_.isOptional()) {
	    buf.append(offset + "  Info: " + info_ + "\n");
	}
	return buf.toString();
    }

    public String toString() {
	return toString("");
    }
}
