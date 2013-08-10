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
import java.math.BigInteger;

import codec.asn1.ASN1Exception;
import codec.asn1.ASN1Integer;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1OctetString;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1SequenceOf;
import codec.asn1.ASN1TaggedType;
import codec.asn1.Decoder;
import codec.x509.GeneralName;
import codec.x509.X509Extension;

/**
 * id-ce-authorityKeyIdentifier OBJECT IDENTIFIER ::= { id-ce 35 }
 * 
 * AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] IMPLICIT
 * KeyIdentifier OPTIONAL, authorityCertIssuer [1] IMPLICIT GeneralNames
 * OPTIONAL, authorityCertSerialNumber [2] IMPLICIT CertificateSerialNumber
 * OPTIONAL }
 * 
 * KeyIdentifier ::= OCTET STRING
 * 
 * CertificateSerialNumber ::= INTEGER
 * 
 * id-ce OBJECT IDENTIFIER ::= {joint-iso-ccitt(2) ds(5) 29}
 * 
 * @author mal
 */
public class AuthorityKeyIdentifierExtension extends X509Extension {
    public static final String ID_CE_AUTHORITY_KEY_IDENTIFIER = "2.5.29.35";

    protected ASN1Sequence authorityKeyIdentifier = new ASN1Sequence(3);

    // key identifier
    public static final int KEY_IDENTIFIER_TYPE = 0;
    private ASN1TaggedType keyIdentifierTag;
    private ASN1OctetString keyIdentifier;

    // cert issuers
    public static final int CERT_ISSUER_TYPE = 1;
    private ASN1TaggedType certIssuerTag;
    private ASN1SequenceOf certIssuer;

    // cert serial number
    public static final int CERT_SERIAL_NUMBER_TYPE = 2;
    private ASN1TaggedType certSerialNumberTag;
    protected ASN1Integer certSerialNumber;

    /**
     * Constructor for SubjectKeyIdentifierExtension.
     * 
     * @throws Exception
     */
    public AuthorityKeyIdentifierExtension() throws Exception {
	super();
	setOID(new ASN1ObjectIdentifier(ID_CE_AUTHORITY_KEY_IDENTIFIER));
	setCritical(false);

	keyIdentifier = new ASN1OctetString();
	keyIdentifierTag = new ASN1TaggedType(KEY_IDENTIFIER_TYPE,
		keyIdentifier, false, true);
	authorityKeyIdentifier.add(keyIdentifierTag);

	certIssuer = new ASN1SequenceOf(GeneralName.class);

	certIssuerTag = new ASN1TaggedType(CERT_ISSUER_TYPE, certIssuer, false,
		true);
	authorityKeyIdentifier.add(certIssuerTag);

	certSerialNumber = new ASN1Integer();
	certSerialNumberTag = new ASN1TaggedType(CERT_SERIAL_NUMBER_TYPE,
		certSerialNumber, false, true);
	authorityKeyIdentifier.add(certSerialNumberTag);

	setValue(authorityKeyIdentifier);
    }

    /**
     * Constructor for SubjectKeyIdentifierExtension.
     * 
     * @param ext
     * @throws ASN1Exception
     * @throws IOException
     */
    public AuthorityKeyIdentifierExtension(byte[] ext) throws ASN1Exception,
	    IOException {
	super(ext);
    }

    /**
     * sets the key identifier, which is normally a hash of the public key.
     * 
     * @param identifier
     *                identifier as byte array.
     */
    public void setKeyIdentifier(byte[] identifier) throws Exception {
	keyIdentifier.setByteArray(identifier);
	keyIdentifierTag.setOptional(false);

	setValue(authorityKeyIdentifier);
    }

    /**
     * adds an issuers of the certs as a GeneralName
     * 
     * @param generalName
     *                the general name
     */
    public void addCertIssuer(GeneralName generalName) throws Exception {
	certIssuer.add(generalName);
	certIssuerTag.setOptional(false);

	setValue(authorityKeyIdentifier);
    }

    /**
     * sets the certificate serial number
     * 
     * @param serialNumber
     *                the serial number of the certificate
     */
    public void setCertSerialNumber(BigInteger serialNumber) throws Exception {
	certSerialNumber.setBigInteger(serialNumber);
	certSerialNumberTag.setOptional(false);

	setValue(authorityKeyIdentifier);
    }

    public void decode(Decoder dec) throws ASN1Exception, IOException {
	super.decode(dec);
	super.decodeExtensionValue(authorityKeyIdentifier);
    }

    /**
     * generates a human readable representation of the object. the
     * representation is indeted using the String offset, if possible.
     * 
     * @param offset
     *                String
     */
    public String toString(String offset) {
	StringBuffer buf = new StringBuffer(offset + "AuthorityKeyIdentifier ["
		+ getOID() + "] {");

	if (isCritical()) {
	    buf.append(" (CRITICAL)\n");
	} else {
	    buf.append(" (NOT CRITICAL)\n");
	}

	if (!keyIdentifierTag.isOptional()) {
	    buf.append(offset + "  keyIdentifier: " + keyIdentifier + "\n");
	}

	if (!certIssuerTag.isOptional()) {
	    buf.append(offset + "  certIssuers: " + certIssuer + "\n");
	}

	if (!certSerialNumberTag.isOptional()) {
	    buf.append(offset + "  certSerialNumber: " + certSerialNumber
		    + "\n");
	}

	buf.append(offset + "}\n");
	return buf.toString();
    }

    public String toString() {
	return toString("");
    }
}
