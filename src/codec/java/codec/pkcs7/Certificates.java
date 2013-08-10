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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Principal;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.ListIterator;

import codec.asn1.ASN1Exception;
import codec.asn1.ASN1Opaque;
import codec.asn1.ASN1Set;
import codec.asn1.ASN1SetOf;
import codec.asn1.Decoder;
import codec.asn1.Encoder;
import codec.util.CertificateIterator;
import codec.util.CertificateSource;

/**
 * Represents a set of certificates. The ASN.1 structure of this type is:
 * <blockquote><code>
 * Certificates ::= SET OF Certificate
 * </code></blockquote>
 * This tye is a convenience type for transporting sets of certificates. It
 * decodes certificates using X.509 certificate factories of the installed
 * providers.
 * <p>
 * 
 * This class des a little optimization - it decodes certificates using the
 * {@link ASN1Opaque ASN1Opaque} type. Therefor, the structure of certificates
 * is not decoded immediately, only the identifier and length octets are
 * decoded. Certificate decoding takes place in a postprocessing step which
 * generates transparent certificate representations using a X.509 certificate
 * factory.
 * 
 * @author Volker Roth
 * @version "$Id: Certificates.java,v 1.2 2000/12/06 17:47:31 vroth Exp $"
 */
public class Certificates extends ASN1SetOf implements CertificateSource {
    /**
     * The certificate factory that is used for decoding certificates.
     */
    protected CertificateFactory factory_;

    /**
     * The cache encoded X.509 certificates. This cache is filled with opaque
     * versions on encoding this instance.
     */
    protected ASN1Set cache_;

    /**
     * Creates an instance ready for decoding.
     */
    public Certificates() {
	super(ASN1Opaque.class);
    }

    /**
     * Decodes this instance using the given decoder. After decoding, the opaque
     * certificates are transformed into instances of X509Certificate by means
     * of a CertificateFactory. If no such factory was set then a default
     * factory of type &quot;X.509&quot; is requested. If no such factory is
     * available then &quot;X509&quot; is tried instead. If neither of these
     * attempts is successful then an ASN1Exception is raised.
     * 
     * @param dec
     *                The decoder to use.
     * @throws ASN1Exception
     *                 if a decoding error occurs.
     * @throws IOException
     *                 if guess what...
     */
    public void decode(Decoder dec) throws ASN1Exception, IOException {
	super.decode(dec);

	int i;
	ASN1Opaque o;
	X509Certificate cert;

	if (factory_ == null) {
	    try {
		factory_ = CertificateFactory.getInstance("X.509");
	    } catch (CertificateException e1) {
		try {
		    factory_ = CertificateFactory.getInstance("X509");
		} catch (CertificateException e2) {
		    throw new ASN1Exception(e2.getMessage());
		}
	    }
	}
	cache_ = null;

	try {
	    for (i = size() - 1; i >= 0; i--) {
		o = (ASN1Opaque) get(i);
		cert = (X509Certificate) factory_
			.generateCertificate(new ByteArrayInputStream(o
				.getEncoded()));

		set(i, cert);
	    }
	} catch (CertificateException e) {
	    throw new ASN1Exception(e.getMessage());
	}
    }

    /**
     * Encodes this using the given {@link Encoder Encoder}. There is a trick
     * behind encoded this instance. Actually not this instance is encoded but a
     * cache that is filled with encoded instances of the certificates in this
     * type.
     * 
     * @param enc
     *                The encoder to use for encoding.
     * @throws ASN1Exception
     *                 if an encoding error occurs.
     * @throws IOException
     *                 if guess what...
     */
    public void encode(Encoder enc) throws ASN1Exception, IOException {
	/*
	 * Optimization: if there are no certificates then we do not have to
	 * worry about certificate conversion.
	 */
	if (isOptional()) {
	    super.encode(enc);
	    return;
	}
	if (cache_ == null) {
	    cache_ = new ASN1Set(size());
	}
	/*
	 * Copy all relevant parameters into the cache instance, e.g. whether we
	 * are tagged EXPLICT, are OPTIONAL etc.
	 */
	cache_.setOptional(isOptional());
	cache_.setExplicit(isExplicit());

	/*
	 * As an invariant I assume that there are at least as many decoded
	 * certificates as there are encoded ones in the cache. This accounts
	 * for the case that this was encoded, then a certificate was added, and
	 * this was encoded again.
	 */
	if (cache_.size() < size()) {
	    X509Certificate cert;
	    ListIterator i;

	    for (i = listIterator(cache_.size()); i.hasNext();) {
		try {
		    cert = (X509Certificate) i.next();
		    cache_.add(new ASN1Opaque(cert.getEncoded()));
		} catch (CertificateEncodingException e) {
		    throw new ASN1Exception(e.getMessage());
		}
	    }
	}
	cache_.encode(enc);
    }

    /**
     * Sets the certificate factory to use for decoding certificates.
     * 
     * @param factory
     *                The certificate factory or <code>null
     *   </code> if the
     *                default <code>X.509</code> factory shall be used.
     */
    public void setCertificateFactory(CertificateFactory factory) {
	factory_ = factory;
    }

    /**
     * Adds the given certificate to this structure if none with the same issuer
     * and serial number already exists.
     * 
     * @param cert
     *                The certificate to add.
     * @return <code>true</code> if the certificate was added and
     *         <code>false</code> if it already existed.
     */
    public boolean addCertificate(X509Certificate cert) {
	Principal issuer;
	BigInteger serial;

	issuer = cert.getIssuerDN();
	serial = cert.getSerialNumber();

	if (getCertificate(issuer, serial) == null) {
	    add(cert);
	    return true;
	}
	return false;
    }

    public X509Certificate getCertificate(Principal issuer, BigInteger serial) {
	X509Certificate cert;
	Iterator i;

	if (issuer == null || serial == null) {
	    throw new NullPointerException("Issuer or serial number!");
	}
	for (i = iterator(); i.hasNext();) {
	    cert = (X509Certificate) i.next();

	    if (issuer.equals(cert.getIssuerDN())
		    && serial.equals(cert.getSerialNumber())) {
		return cert;
	    }
	}
	return null;
    }

    public Iterator certificates(Principal subject) {
	return new CertificateIterator(subject, CertificateSource.ALL,
		iterator());
    }

    public Iterator certificates(Principal subject, int keyUsage) {
	return new CertificateIterator(subject, keyUsage, iterator());
    }

}
