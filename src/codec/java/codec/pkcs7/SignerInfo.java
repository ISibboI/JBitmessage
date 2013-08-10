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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import codec.InconsistentStateException;
import codec.asn1.ASN1Exception;
import codec.asn1.ASN1Integer;
import codec.asn1.ASN1Null;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1OctetString;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1TaggedType;
import codec.asn1.ASN1Type;
import codec.asn1.DEREncoder;
import codec.asn1.Encoder;
import codec.asn1.OIDRegistry;
import codec.pkcs9.Attributes;
import codec.util.JCA;
import codec.x501.Attribute;
import codec.x501.BadNameException;
import codec.x501.Name;
import codec.x509.AlgorithmIdentifier;
import codec.x509.SubjectPublicKeyInfo;

/**
 * ATTENTION : if this object shall use the strict DER encoding rules, the
 * function setStrict(true) must be called right after instantiating the object.
 * 
 * This class represents a PKCS#7 SignerInfo structure. It is defined as
 * follows:
 * 
 * <pre>
 * SignerInfo ::= SEQUENCE {
 *   version Version,
 *   issuerAndSerialNumber IssuerAndSerialNumber,
 *   digestAlgorithm DigestAlgorithmIdentifier,
 *   authenticatedAttributes [0] IMPLICIT Attributes OPTIONAL,
 *   digestEncryptionAlgorithm DigestEncryptionAlgorithmIdentifier,
 *   encryptedDigest EncryptedDigest,
 *   unauthenticatedAttributes [1] IMPLICIT Attributes OPTIONAL
 * }
 * EncryptedDigest ::= OCTET STRING
 * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
 * DigestEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
 * </pre>
 * 
 * For completeness, we also present the structures referenced in the SignerInfo
 * structure.
 * 
 * <pre>
 * IssuerAndSerialNumber ::= SEQUENCE {
 *   issuer Name,
 *   serialNumber CertificateSerialNumber
 * }
 * CertificateSerialNumber ::= INTEGER
 * Attributes ::= SET OF Attribute -- from X.501
 * </pre>
 * 
 * @author Volker Roth
 * @version "$Id: SignerInfo.java,v 1.3 2004/08/12 12:31:42 pebinger Exp $"
 */
public class SignerInfo extends ASN1Sequence {
    /**
     * The version number of this SignerInfo.
     */
    protected ASN1Integer version_;

    /**
     * The issuer name. Still of type ANY but being replaced by RDName soon.
     */
    protected Name issuer_;

    /**
     * The serial number.
     */
    protected ASN1Integer serial_;

    /**
     * The {@link AlgorithmIdentifier DigestAlgorithmIdentifier}.
     */
    protected AlgorithmIdentifier dAlg_;

    /**
     * The {@link AlgorithmIdentifier DigestEncryptionAlgorithmIdentifier}.
     */
    protected AlgorithmIdentifier cAlg_;

    /**
     * The authenticated attributes.
     */
    protected Attributes auth_;

    /**
     * The unauthenticated attributes.
     */
    protected Attributes attr_;

    /**
     * The encrypted digest.
     */
    protected ASN1OctetString edig_;

    /**
     * The algorithm to use when a {@link SignedData SignedData} instance is
     * used for signing or verifying.
     */
    protected String algorithm_;

    /**
     * The signature algorithm parameters spec to use when verifying or signing
     * {@link SignedData SignedData} instances.
     */
    protected AlgorithmParameterSpec spec_;

    /**
     * if true, the strict DER encoding is used.
     */
    private boolean strict = false;

    /**
     * Creates an instance ready for decoding.
     */
    public SignerInfo() {
	super(7);

	ASN1Sequence seq;

	/* Global structure and Version */
	version_ = new ASN1Integer(1);
	add(version_);

	/* Issuer and serial number */
	issuer_ = new Name();
	serial_ = new ASN1Integer();

	seq = new ASN1Sequence(2);
	seq.add(issuer_);
	seq.add(serial_);

	add(seq);

	/* Digest Algorithm Identifier */
	dAlg_ = new AlgorithmIdentifier();
	add(dAlg_);

	/* Authenticated Attributes */
	auth_ = new Attributes();
	add(new ASN1TaggedType(0, auth_, false, true));

	/* Digest Encryption Algorithm Identifier */
	cAlg_ = new AlgorithmIdentifier();
	add(cAlg_);

	/* Encrypted Digest */
	edig_ = new ASN1OctetString();
	add(edig_);

	/* Unauthenticated Attributes */
	attr_ = new Attributes();
	add(new ASN1TaggedType(1, attr_, false, true));
    }

    /**
     * Creates an instance ready for decoding. The given registry is used to
     * resolve attributes.
     * 
     * @param registry
     *                The <code>OIDRegistry</code> to use for resolving
     *                attributes, or <code>null</code> if the default PKCS
     *                registry shall be used.
     */
    public SignerInfo(OIDRegistry registry) {
	super(7);

	ASN1Sequence seq;

	/* Global structure and Version */
	version_ = new ASN1Integer(1);
	add(version_);

	/* Issuer and serial number */
	issuer_ = new Name();
	serial_ = new ASN1Integer();

	seq = new ASN1Sequence(2);
	seq.add(issuer_);
	seq.add(serial_);

	add(seq);

	/* Digest Algorithm Identifier */
	dAlg_ = new AlgorithmIdentifier();
	add(dAlg_);

	/* Authenticated Attributes */
	auth_ = new Attributes(registry);
	add(new ASN1TaggedType(0, auth_, false, true));

	/* Digest Encryption Algorithm Identifier */
	cAlg_ = new AlgorithmIdentifier();
	add(cAlg_);

	/* Encrypted Digest */
	edig_ = new ASN1OctetString();
	add(edig_);

	/* Unauthenticated Attributes */
	attr_ = new Attributes(registry);
	add(new ASN1TaggedType(1, attr_, false, true));
    }

    /**
     * This method calls initializes this structure with the given arguments.
     * This constructore creates Version 1 SignerInfos. The given algorithm must
     * be a PKCS#1 Version 1.5 conformant signature algorithm. In other words,
     * the signature algorithm MUST NOT have algorithm parameters beyond those
     * embedded in the {@link SubjectPublicKeyInfo SubjectPublicKeyInfo} of the
     * public key, and aliases for a slashed name form MUST be defined by JSPs
     * (Java Security Providers). JSPs also MUST define OID aliases for the
     * signature's raw cipher and the message digest.
     * <p>
     * 
     * If PKCS#1 version 2.1 Draft 1 signatures (RSASSA-PSS) shall be used then
     * the constructor taking algorithm parameters must be called instead of
     * this one.
     * 
     * @param cert
     *                The signer's certificate.
     * @param algorithm
     *                The JCA standard name of the PKCS#1 version 1.5 compliant
     *                signature algorithm.
     * @throws NoSuchAlgorithmException
     *                 if the signature algorithm name cannot be resolved to the
     *                 OIDs of the names of its raw cipher algorithm and its
     *                 digest algorithm.
     * @throws BadNameException
     *                 if the issuer name in the given certificate cannot be
     *                 parsed.
     * @throws IllegalArgumentException
     *                 if the OID to which the given algorithm name is mapped by
     *                 means of the aliases of the installed providers is not a
     *                 valid OID string.
     */
    public SignerInfo(X509Certificate cert, String algorithm)
	    throws BadNameException, NoSuchAlgorithmException {
	super(7);

	ASN1Sequence seq;
	String d;
	String c;

	/* Global structure and Version */
	version_ = new ASN1Integer(1);
	add(version_);

	/* Issuer and serial number */
	issuer_ = new Name(cert.getIssuerDN().getName(), -1);
	serial_ = new ASN1Integer(cert.getSerialNumber());

	seq = new ASN1Sequence(2);
	seq.add(issuer_);
	seq.add(serial_);

	add(seq);

	/*
	 * We now initialize the algorithm identifiers. The style is according
	 * to PKCS#1 Version 1.5, no parameters for the signature algorithm.
	 * Parameters are encoded as ASN1Null.
	 */
	d = JCA.getDigestOID(algorithm);
	c = JCA.getCipherOID(algorithm);
	if (d == null || c == null) {
	    throw new NoSuchAlgorithmException(
		    "Cannot resolve signature algorithm!");
	}
	try {
	    dAlg_ = new AlgorithmIdentifier(new ASN1ObjectIdentifier(d),
		    new ASN1Null());
	    cAlg_ = new AlgorithmIdentifier(new ASN1ObjectIdentifier(c),
		    new ASN1Null());
	} catch (ASN1Exception e) {
	    throw new InconsistentStateException(e);
	}
	/* Digest Algorithm Identifier */
	add(dAlg_);

	/* Authenticated Attributes */
	auth_ = new Attributes();
	add(new ASN1TaggedType(0, auth_, false, true));

	/* Digest Encryption Algorithm Identifier */
	add(cAlg_);

	/* Encrypted Digest */
	edig_ = new ASN1OctetString();
	add(edig_);

	/* Unauthenticated Attributes */
	attr_ = new Attributes();
	add(new ASN1TaggedType(1, attr_, false, true));

	algorithm_ = algorithm;
    }

    /**
     * method as above, but with an explicit encoding type
     * 
     * @param cert
     * @param algorithm
     * @param nameEncoding
     * @throws BadNameException
     * @throws NoSuchAlgorithmException
     */

    public SignerInfo(X509Certificate cert, String algorithm, int nameEncoding)
	    throws BadNameException, NoSuchAlgorithmException {
	super(7);

	ASN1Sequence seq;
	String d;
	String c;

	/* Global structure and Version */
	version_ = new ASN1Integer(1);
	add(version_);

	/* Issuer and serial number */
	// System.out.println("Choosen Printable");
	issuer_ = new Name(cert.getIssuerDN().getName(), nameEncoding);
	serial_ = new ASN1Integer(cert.getSerialNumber());

	seq = new ASN1Sequence(2);
	seq.add(issuer_);
	seq.add(serial_);

	add(seq);

	/*
	 * We now initialize the algorithm identifiers. The style is according
	 * to PKCS#1 Version 1.5, no parameters for the signature algorithm.
	 * Parameters are encoded as ASN1Null.
	 */
	d = JCA.getDigestOID(algorithm);
	c = JCA.getCipherOID(algorithm);
	if (d == null || c == null) {
	    throw new NoSuchAlgorithmException(
		    "Cannot resolve signature algorithm!");
	}
	try {
	    dAlg_ = new AlgorithmIdentifier(new ASN1ObjectIdentifier(d),
		    new ASN1Null());
	    cAlg_ = new AlgorithmIdentifier(new ASN1ObjectIdentifier(c),
		    new ASN1Null());
	} catch (ASN1Exception e) {
	    throw new InconsistentStateException(e);
	}
	/* Digest Algorithm Identifier */
	add(dAlg_);

	/* Authenticated Attributes */
	auth_ = new Attributes();
	add(new ASN1TaggedType(0, auth_, false, true));

	/* Digest Encryption Algorithm Identifier */
	add(cAlg_);

	/* Encrypted Digest */
	edig_ = new ASN1OctetString();
	add(edig_);

	/* Unauthenticated Attributes */
	attr_ = new Attributes();
	add(new ASN1TaggedType(1, attr_, false, true));

	algorithm_ = algorithm;
    }

    /**
     * This method calls initializes this structure with the given arguments.
     * This constructore creates Version 1 SignerInfos. The given algorithm must
     * be a PKCS#1 Version 2.1 Draft 1 conformant signature algorithm. The
     * signature algorithm identifier is put into the place of the digest
     * algorithm identifier. The given parameters are those of the signature
     * algorithm (e. g. RSASSA-PSS). If the parameters are <code>null</code>
     * then they are encoded as {@link ASN1Null ASN1Null}. The signature
     * algorithm identifier is also put into the place of the digest encryption
     * algorithm identifier (without parameters). PKCS#1 Version 2.1 Draft 1
     * does not specify how this case should be handled so we picked our choice.
     * 
     * @param cert
     *                The signer's certificate.
     * @param algorithm
     *                The JCA standard name of the PKCS#1 Version 2.1 Draft 1
     *                compliant signature algorithm.
     * @throws NoSuchAlgorithmException
     *                 if the signature algorithm name cannot be resolved to the
     *                 OIDs of the names of its raw cipher algorithm and its
     *                 digest algorithm.
     * @throws BadNameException
     *                 if the issuer name in the given certificate cannot be
     *                 parsed.
     */
    public SignerInfo(X509Certificate cert, String algorithm,
	    AlgorithmParameters params) throws BadNameException,
	    NoSuchAlgorithmException, InvalidAlgorithmParameterException {
	super(7);

	ASN1Sequence seq;
	String s;

	/* Global structure and Version */
	version_ = new ASN1Integer(1);
	add(version_);

	/* Issuer and serial number */
	issuer_ = new Name(cert.getIssuerDN().getName(), -1);
	serial_ = new ASN1Integer(cert.getSerialNumber());

	seq = new ASN1Sequence(2);
	seq.add(issuer_);
	seq.add(serial_);

	add(seq);

	/*
	 * We now initialize the algorithm identifiers. The style is PKCS#1
	 * Version 2.1 Draft 1 with the signature algorithm identifier in the
	 * place of the digest algorithm identifier.
	 */
	s = JCA.getOID(algorithm);
	if (s == null) {
	    throw new NoSuchAlgorithmException(
		    "Cannot resolve signature algorithm!");
	}
	dAlg_ = new AlgorithmIdentifier(s, params);
	cAlg_ = new AlgorithmIdentifier(s);

	/* Digest Algorithm Identifier */
	add(dAlg_);

	/* Authenticated Attributes */
	auth_ = new Attributes();
	add(new ASN1TaggedType(0, auth_, false, true));

	/* Digest Encryption Algorithm Identifier */
	add(cAlg_);

	/* Encrypted Digest */
	edig_ = new ASN1OctetString();
	add(edig_);

	/* Unauthenticated Attributes */
	attr_ = new Attributes();
	add(new ASN1TaggedType(1, attr_, false, true));

	algorithm_ = algorithm;
	if (params != null) {
	    try {
		spec_ = params.getParameterSpec(AlgorithmParameterSpec.class);
	    } catch (InvalidParameterSpecException e) {
		throw new InvalidAlgorithmParameterException(
			"Cannot transform params to spec!");
	    }
	}
    }

    /**
     * same as above but with an explicit nameEncoding.
     * 
     * @param cert
     * @param algorithm
     * @param params
     * @param nameEncoding
     * @throws BadNameException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     */
    public SignerInfo(X509Certificate cert, String algorithm,
	    AlgorithmParameters params, int nameEncoding)
	    throws BadNameException, NoSuchAlgorithmException,
	    InvalidAlgorithmParameterException {
	super(7);

	ASN1Sequence seq;
	String s;

	/* Global structure and Version */
	version_ = new ASN1Integer(1);
	add(version_);

	/* Issuer and serial number */
	issuer_ = new Name(cert.getIssuerDN().getName(), nameEncoding);
	serial_ = new ASN1Integer(cert.getSerialNumber());

	seq = new ASN1Sequence(2);
	seq.add(issuer_);
	seq.add(serial_);

	add(seq);

	/*
	 * We now initialize the algorithm identifiers. The style is PKCS#1
	 * Version 2.1 Draft 1 with the signature algorithm identifier in the
	 * place of the digest algorithm identifier.
	 */
	s = JCA.getOID(algorithm);
	if (s == null) {
	    throw new NoSuchAlgorithmException(
		    "Cannot resolve signature algorithm!");
	}
	dAlg_ = new AlgorithmIdentifier(s, params);
	cAlg_ = new AlgorithmIdentifier(s);

	/* Digest Algorithm Identifier */
	add(dAlg_);

	/* Authenticated Attributes */
	auth_ = new Attributes();
	add(new ASN1TaggedType(0, auth_, false, true));

	/* Digest Encryption Algorithm Identifier */
	add(cAlg_);

	/* Encrypted Digest */
	edig_ = new ASN1OctetString();
	add(edig_);

	/* Unauthenticated Attributes */
	attr_ = new Attributes();
	add(new ASN1TaggedType(1, attr_, false, true));

	algorithm_ = algorithm;
	if (params != null) {
	    try {
		spec_ = params.getParameterSpec(AlgorithmParameterSpec.class);
	    } catch (InvalidParameterSpecException e) {
		throw new InvalidAlgorithmParameterException(
			"Cannot transform params to spec!");
	    }
	}
    }

    /**
     * sets the strict parameter with the given value.
     */
    public void setStrict(boolean strictness) {
	this.strict = strictness;
    }

    /**
     * This method updates the given Signature instance with the DER encoding of
     * the <code>authenticatedAttributes
     * </code> file of the SignerInfo
     * structure if such attributes are given.
     * 
     * @param sig
     *                The Signature instance to be updated.
     * @throws SignatureException
     *                 if the signature instance is not properly initialized.
     * @throws InconsistentStateException
     *                 in case of an internal error -- this should never happen.
     */
    public void update(Signature sig) throws SignatureException {
	if (sig == null)
	    throw new NullPointerException("Sig is null!");

	if (auth_.size() > 0) {
	    ByteArrayOutputStream bos;
	    DEREncoder enc;

	    try {
		bos = new ByteArrayOutputStream();
		enc = new DEREncoder(bos);
		if (this.strict)
		    enc.setStrict(true);

		/*
		 * Because the authenticated attributes are tagged IMPLICIT in
		 * version 1.5 we have to set tagging to EXPLICIT during
		 * encoding. Otherwise the identifier and length octets would be
		 * missing in the encoding.
		 */
		auth_.setExplicit(true);
		auth_.encode(enc);

		sig.update(bos.toByteArray());

		enc.close();
	    } catch (ASN1Exception e) {
		throw new InconsistentStateException(e);
	    } catch (IOException e) {
		throw new InconsistentStateException(e);
	    } finally {
		/*
		 * No matter what happens, in order to maintain the consistency
		 * of the internal structure we have to set the tagging of the
		 * authenticated attributes back to IMPLICIT.
		 */
		auth_.setExplicit(false);
	    }
	}
    }

    /**
     * This method sets the encrypted digest.
     * 
     * @param edig
     *                The encrypted digest.
     */
    public void setEncryptedDigest(byte[] edig) {
	edig_ = new ASN1OctetString(edig);
	set(5, edig_);
    }

    /**
     * This method returns the encrypted digest stored in this structure. The
     * EncryptedDigest is defined as
     * 
     * <pre>
     * EncryptedDigest ::= OCTET STRING
     * </pre>
     * 
     * This octet string contains the encrypted digest info structure, which is
     * reproduced below for completeness:
     * 
     * <pre>
     * DigestInfo ::= SEQUENCE {
     *   digestAlgorithm DigestAlgorithmIdentifier,
     *   digest Digest
     * }
     * Digest ::= OCTET STRING
     * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
     * </pre>
     * 
     * @return The encrypted digest.
     */
    public byte[] getEncryptedDigest() {
	return edig_.getByteArray();
    }

    /**
     * Returns the authenticated attributes.
     * 
     * @return The unmodifiable list of authenticated attributes.
     */
    public Attributes authenticatedAttributes() {
	return auth_;
    }

    /**
     * Adds the given {@link Attribute attribute} to the list of authenticated
     * attributes. This method should be used to add attributes because it
     * clears the attributes instance's <code>OPTIONAL</code> flag.
     * Alternatively, this can be done manually.
     * 
     * @param attr
     *                The attribute.
     */
    public void addAuthenticatedAttribute(Attribute attr) {
	if (attr == null)
	    throw new NullPointerException("Need an attribute!");

	auth_.add(attr);
    }

    /**
     * Returns the unauthenticated attributes.
     * 
     * @return The unmodifiable list of unauthenticated attributes.
     */
    public Attributes unauthenticatedAttributes() {
	return attr_;
    }

    /**
     * Adds the given {@link Attribute attribute} to the list of unauthenticated
     * attributes. This method should be used to add attributes because it
     * clears the attributes instance's <code>OPTIONAL</code> flag.
     * Alternatively, this can be done manually.
     * 
     * @param attr
     *                The attribute.
     */
    public void addUnauthenticatedAttribute(Attribute attr) {
	if (attr == null)
	    throw new NullPointerException("Need an attribute!");

	attr_.add(attr);
    }

    /**
     * Returns the {@link Name name} of the issuer of the certificate of this
     * signer.
     * 
     * @return The issuer name.
     */
    public Principal getIssuerDN() {
	return issuer_;
    }

    /**
     * 
     * @return The serial number.
     */
    public BigInteger getSerialNumber() {
	return serial_.getBigInteger();
    }

    /**
     * This method returns the DigestAlgorithmIdentifier.
     * 
     * @return The DigestAlgorithmIdentifier.
     */
    public AlgorithmIdentifier getDigestAlgorithmIdentifier() {
	return dAlg_;
    }

    /**
     * Returns the name of the signature algorithm. This method calls
     * {@link #init init()} if the name is not yet known in order to determine
     * it by means of the {@link JCA JCA} and the
     * {@link AlgorithmIdentifier algorithm identifiers} embedded in this
     * structure.
     * 
     * @return The algorithm name.
     * @throws NoSuchAlgorithmException
     *                 if the OIDs in this structure cannot be mapped onto an
     *                 algorithm name by means of the alias definitions of the
     *                 installed providers.
     * @throws InvalidAlgorithmParameterException
     *                 if the signature algorithm identifier contains parameters
     *                 but the parameters cannot be decoded.
     */
    public String getAlgorithm() throws NoSuchAlgorithmException,
	    InvalidAlgorithmParameterException {
	if (algorithm_ == null)
	    init();

	return algorithm_;
    }

    /**
     * Returns the algorithm parameter spec for the parameters of the signature
     * algorithm (PKCS#1 Version 2.1 Draft 1) or <code>null</code> if there
     * are none.
     * 
     * @return The AlgorithmParameterSpec to use when initializing the signature
     *         engine.
     * @throws NoSuchAlgorithmException
     *                 if the OIDs in this structure cannot be mapped onto an
     *                 algorithm name by means of the alias definitions of the
     *                 installed providers.
     * @throws InvalidAlgorithmParameterException
     *                 if the signature algorithm identifier contains parameters
     *                 but the parameters cannot be decoded.
     */
    public AlgorithmParameterSpec getParameterSpec()
	    throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
	if (spec_ == null)
	    init();

	return spec_;
    }

    /**
     * This method determines the signature algorithm and appropriate parameters
     * for initializing the signature algorithm from the algorithm identifiers
     * in this structure. PKCS#1 versions 1.5 and 2.1 Draft 1 are supported.
     * <p>
     * 
     * We start by resolving the digest and cipher OIDs against a signature
     * algorithm name by means of the {@link JCA JCA} class. This requires JSPs
     * (Java Security Providers) to support appropriate alias mappings. Both OID
     * mappings and slashed forms are required.
     * <p>
     * 
     * If this fails then we try to interpret the digest algorithm identifier as
     * the signature algorithm identifier. If this still does not give us a
     * valid signature engine then we try the digest encryption algorithm
     * identifier as the signature algorithm identifier.
     * <p>
     * 
     * If the combined form led to the signature engine then no parameters are
     * set (apart from those in the public key's
     * {@link SubjectPublicKeyInfo SubjectPublicKeyInfo}. If either the digest
     * algorithm identifier or the digest encryption algorithm identifier led to
     * the signature engine then the respective parameters are set for the
     * signature engine.
     * <p>
     * 
     * Parameters are set before the signature engine is initialized with the
     * public key. No hint is given in the JDK documentation on which is to be
     * done first. So we picked our choice.
     * <p>
     * 
     * Parameter initialization works only if the parameters engine supports
     * proper conversion of opaque parameter representations into transparent
     * representations (AlgorithmParameterSpecs) by means of the
     * <code>getAlgorithmParameterSpec()</code> method. Hardly any provider
     * gets it right, at the time of writing not even the Sun JSP does it
     * correctly.
     */
    protected void init() throws NoSuchAlgorithmException,
	    InvalidAlgorithmParameterException {
	AlgorithmParameters params;
	String d;
	String c;
	String s;

	d = dAlg_.getAlgorithmOID().toString();
	c = cAlg_.getAlgorithmOID().toString();
	s = JCA.getSignatureName(d, c);

	if (s != null) {
	    algorithm_ = s;
	    return;
	}
	/*
	 * If we cannot resolve the combined digest/cipher name to a signature
	 * alg name then we try the digest algorithm identifier instead. This is
	 * the recommended way as of PKCS#1 Version 2.1 Draft 1.
	 */
	s = JCA.resolveAlias("Signature", d);

	if (s != null) {
	    algorithm_ = s;
	    params = dAlg_.getParameters();
	} else {
	    /*
	     * If we cannot get an instance by ordinary means then we try the
	     * cipher algorithm identifier as a last resort. This is not
	     * standard however.
	     */
	    s = JCA.resolveAlias("Signature", c);

	    if (s != null) {
		algorithm_ = s;
		params = cAlg_.getParameters();
	    } else {
		throw new NoSuchAlgorithmException("Cannot resolve OIDs!");
	    }
	}
	try {
	    spec_ = (params == null) ? null : params
		    .getParameterSpec(AlgorithmParameterSpec.class);
	} catch (InvalidParameterSpecException e) {
	    throw new InvalidAlgorithmParameterException(
		    "Cannot convert params into spec!");
	}
    }

    /**
     * Checks if this <code>SignerInfo</code> has an issuer distinguished name
     * and a serial number that are equivalent to those in the given
     * certificate.
     * 
     * @param cert
     *                The certificate to compare to.
     * @return <code>true</code> if this <code>SignerInfo
     *   </code> matches the
     *         given certificate.
     */
    public boolean equivIssuerAndSerialNumber(X509Certificate cert) {
	if (cert == null)
	    throw new NullPointerException("Need a cert!");

	if (!issuer_.equals(cert.getIssuerDN()))
	    return false;

	return serial_.getBigInteger().equals(cert.getSerialNumber());
    }

    /**
     * Returns a string representation of this object.
     * 
     * @return The string representation.
     */
    public String toString() {
	StringBuffer buf;
	String alg;

	try {
	    alg = getAlgorithm();
	} catch (Exception e) {
	    alg = "<unknown>";
	}
	buf = new StringBuffer();
	buf.append("PKCS#7 SignerInfo {\n" + "Version   : "
		+ version_.toString() + "\n" + "Issuer    : "
		+ issuer_.getName() + "\n" + "Serial    : "
		+ serial_.toString() + "\n" + "Algorithm : " + alg + "\n"
		+ "Auth A    : " + auth_.size() + " elements\n"
		+ "Unauth A  : " + attr_.size() + " elements\n"
		+ "Signature : " + edig_.toString() + "\n");

	if (auth_.size() > 0) {
	    buf.append("\n" + auth_);
	}
	buf.append("}\n");

	return buf.toString();
    }

    /**
     * Encodes this <code>SignerInfo</code>.
     * 
     * @param encoder
     *                The encoder to use.
     */
    public void encode(Encoder encoder) throws IOException, ASN1Exception {
	/*
	 * Yet another nail in my coffin...
	 */
	ASN1Type t;
	boolean opt;

	t = (ASN1Type) get(3);
	opt = (auth_.size() == 0);
	t.setOptional(opt);

	t = (ASN1Type) get(6);
	opt = (attr_.size() == 0);
	t.setOptional(opt);

	super.encode(encoder);
    }

}
