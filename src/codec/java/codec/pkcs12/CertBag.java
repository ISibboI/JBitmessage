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

import java.io.ByteArrayInputStream;
import java.io.IOException;

import codec.asn1.ASN1Exception;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1OctetString;
import codec.asn1.ASN1OpenType;
import codec.asn1.ASN1RegisteredType;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1TaggedType;
import codec.asn1.ASN1Type;
import codec.asn1.Decoder;

/**
 * This class represents a <code>certBag</code> as defined in <a
 * href="http://www.rsasecurity.com/rsalabs/pkcs/pkcs-12/index.html">PKCS#12</a>.
 * The ASN.1 definition of this structure is
 * 
 * <pre>
 * certBag ::= SEQUENCE {
 *   certId       BAG-TYPE.&amp;id ({CertTypes}),
 *   certValue    [0] EXPLICIT BAG-TYPE.&amp;Type ({CertTypes}{&#0064;certId})
 * }
 * 
 * x509Certificate BAG-TYPE::=
 *        {OCTET STRING IDENTIFIED BY {certTypes 1}} -- DER encoded X.509 certificate stored in OCTET STRING
 *        
 * sdsiCertificate BAG-TYPE::=
 *        {IA5String IDENTIFIED BY {certTypes 2}}    -- Base64 encoded SDSI certificate stored in IA5String
 *        
 * CertTypes BAG-TYPE::={
 *        x509Certificate|
 *        sdsiCertificate|
 *        ...                                        -- For future extensions
 * </pre>
 * 
 * @author Michele Boivin
 * @version "$Id: CertBag.java,v 1.4 2005/03/22 14:01:56 flautens Exp $"
 */
public class CertBag extends ASN1Sequence implements ASN1RegisteredType,
	java.io.Serializable {
    /**
     * The OID of this structure.
     */
    private static final int[] OID_ = { 1, 2, 840, 113549, 1, 12, 10, 1, 3 };

    /**
     * The certificate identifier.
     */
    private ASN1ObjectIdentifier certId_;

    /**
     * The actual value of the certificate.
     */
    private ASN1TaggedType certValue_;

    /**
     * The x.509 DER encoded Certificate
     */
    private ASN1OctetString x509Cert_;

    /**
     * DOCUMENT ME!
     */
    protected PKCS12OIDRegistry reg_ = new PKCS12OIDRegistry();

    // /**
    // * The sdsi DER encoded Certificate
    // */
    // protected ASN1IA5String sdsiCert_;

    /**
     * The default constructor.
     */
    public CertBag() {
	super(2);
	certId_ = new ASN1ObjectIdentifier();
	add(certId_);
	ASN1OpenType ot = new ASN1OpenType(reg_, certId_);
	certValue_ = new ASN1TaggedType(0, ot, true);
	add(certValue_);
    }

    /**
     * Constructor for a x.509 certBag. The octet string holds the DER encoded
     * x.509 certificate.
     * 
     * @param cert
     *                the certicifate
     */
    public CertBag(java.security.cert.X509Certificate cert)
	    throws java.security.cert.CertificateEncodingException {
	super(2);
	certId_ = new ASN1ObjectIdentifier("1.2.840.113549.1.9.22.1");
	add(certId_);
	x509Cert_ = new ASN1OctetString(cert.getEncoded());
	certValue_ = new ASN1TaggedType(0, x509Cert_, true);
	add(certValue_);
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

	t = certValue_.getInnerType();
	if (t instanceof ASN1OpenType) {
	    o = (ASN1OpenType) t;
	    certValue_.setInnerType(o.getInnerType());
	}
    }

    /**
     * @return The OID describing the <code>certValue</code> of this
     *         structure.
     */
    public ASN1ObjectIdentifier getCertId() {
	return certId_;
    }

    /**
     * @return The value of the certficate bag. In case of a x509 certificate
     *         the ASN1OctetString holding the DER encoded x509certificate.
     */
    public java.security.cert.X509Certificate getCertificate()
	    throws java.security.cert.CertificateException {
	byte[] derCert = ((ASN1OctetString) certValue_.getInnerType())
		.getByteArray();
	ByteArrayInputStream bais = new ByteArrayInputStream(derCert);

	java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory
		.getInstance("X.509");
	java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate) cf
		.generateCertificate(bais);

	try {
	    bais.close();
	} catch (IOException io) {
	    System.out.println("Internal error. shouldn't happen:");
	    io.printStackTrace();
	}

	return cert;
    }

    /**
     * @return The value of the certficate bag. In case of a x509 certificate
     *         the ASN1OctetString holding the DER encoded x509certificate.
     */
    public ASN1Type getCertValue() {
	return certValue_.getInnerType();
    }

    /**
     * @return the OID for this bag type.
     */
    public ASN1ObjectIdentifier getOID() {
	return new ASN1ObjectIdentifier(OID_);
    }
}
