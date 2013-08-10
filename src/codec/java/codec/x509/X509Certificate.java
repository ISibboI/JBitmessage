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
package codec.x509;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Externalizable;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Set;
import java.util.TimeZone;

import codec.CorruptedCodeException;
import codec.asn1.ASN1BitString;
import codec.asn1.ASN1Exception;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1Type;
import codec.asn1.Constraint;
import codec.asn1.ConstraintException;
import codec.asn1.DERDecoder;
import codec.asn1.DEREncoder;
import codec.asn1.Decoder;
import codec.asn1.Encoder;

/**
 * Implements a X.509v3 certificate according to the following ASN.1 data
 * structure:
 * <p>
 * 
 * <pre>
 * Certificate  ::=  SEQUENCE  {
 * tbsCertificate			TBSCertificate,
 * signatureAlgorithm		AlgorithmIdentifier,
 * signatureValue      	BIT STRING
 * }
 * </pre>
 * 
 * If you want to create a certificate, follow these steps:
 * <li>create a {@link X509TBSCertificate X509TBSCertificate} object and fill
 * it with sensible data
 * <li>call the {@link #X509Certificate(X509TBSCertificate)} constructor and
 * pass the tbsCertificate as an argument
 * <li>call {@link #setSignature(byte[]) setSignature} with a pre-computed
 * signature of the tbsCertificate
 * <li>{@link #getEncoded() getEncoded()} will return the DER-encoded
 * certificate as a Byte array.
 * <p>
 * Example:
 * 
 * <pre>
 * PrivateKey CASigningKey = ...;
 * X509Certificate CASignatureCert = ...;
 * PublicKey subjectPublicKey = ...;
 * Name issuerDN = new Name(&quot;cn=My CA, c=DE&quot;);
 * Name subjectDN = new Name(&quot;cn=Myself, c=DE&quot;);
 * Calendar validFrom = ...;
 * Calendar validUntil = ...;
 * X509TBSCertificate tbs = new X509TBSCertificate();
 * tbs.setSerialNumber(new BigInteger(&quot;1&quot;));
 * tbs.setSubjectPublicKey(subjectPublicKey);
 * tbs.setSubjectDN(subjectDN);
 * tbs.setIssuerDN(issuerDN);
 * tbs.setNotBefore(validFrom);
 * tbs.setNotAfter(validUntil);
 * X509Certificate theCert = new X509Certificate(tbs);
 * Signature mySig = Signature.getInstance(...);
 * mySig.initSign(CASigningKey);
 * theCert.sign(mySig, CASignatureCert);
 * </pre>
 * 
 * @author Markus Tak
 */
public class X509Certificate extends java.security.cert.X509Certificate
	implements ASN1Type, Externalizable {

    private ASN1Sequence Certificate_ = null;
    private X509TBSCertificate tbsCertificate_ = null;
    private AlgorithmIdentifier signatureAlgorithm_ = null;
    private ASN1BitString signatureValue_ = null;

    /**
     * Constructor that builds the data structure
     */
    public X509Certificate() {

	Certificate_ = new ASN1Sequence(3);

	tbsCertificate_ = new X509TBSCertificate();
	Certificate_.add(tbsCertificate_);

	signatureAlgorithm_ = new codec.x509.AlgorithmIdentifier();
	Certificate_.add(signatureAlgorithm_);

	signatureValue_ = new ASN1BitString();
	Certificate_.add(signatureValue_);

    }

    /**
     * Contructor upon a DER-encoded Byte-Array
     */
    public X509Certificate(byte[] cert)
	    throws java.security.cert.CertificateEncodingException {

	this();

	try {
	    ByteArrayInputStream bais = new ByteArrayInputStream(cert);
	    decode(new DERDecoder(bais));
	    bais.close();
	} catch (Exception e) {
	    throw new java.security.cert.CertificateEncodingException(e
		    .getMessage());
	}

    }

    /**
     * Constructor upon an InputStream
     */
    public X509Certificate(InputStream in)
	    throws java.security.cert.CertificateEncodingException {
	this();

	try {
	    decode(new DERDecoder(in));
	} catch (Exception e) {
	    throw new java.security.cert.CertificateEncodingException(e
		    .getMessage());
	}
    }

    /**
     * Constructor upon a TBSCertificate. Use this one if you want to create a
     * certificate.
     */
    public X509Certificate(X509TBSCertificate tbs) {
	this();
	setTBSCertificate(tbs);

    }

    /**
     * From interface ASN1Type
     */
    public void setConstraint(Constraint c) {
	Certificate_.setConstraint(c);
    }

    /**
     * From interface ASN1Type
     */
    public Constraint getConstraint() {
	return Certificate_.getConstraint();
    }

    /**
     * Adds an extension to this certificate. Version info is updated
     * automatically to "V3"
     * 
     * @param ext
     *                the Extension to be added
     */
    public void addExtension(X509Extension ext) {
	tbsCertificate_.addExtension(ext);
    }

    /**
     * From interface ASN1Type
     */
    public void checkConstraints() throws ConstraintException {
	Certificate_.checkConstraints();
    }

    /**
     * From java.security.cert.X509Certificate. Checks the validity period of
     * this certificate against the actual date. The actual date is obtained via
     * Calendar.getInstance(GMT).
     * 
     * @throws CertificateExpiredException
     * @throws CertificateNotYetValidException
     */
    public void checkValidity() throws CertificateExpiredException,
	    CertificateNotYetValidException {

	Calendar now = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
	checkValidity(now.getTime());

    }

    /**
     * From java.security.cert.X509Certificate. Checks the validity period of
     * this certificate against the given date.
     * 
     * @param date
     *                Date to be checked against the validity period of this
     *                certificate
     * @throws CertificateExpiredException
     *                 if the certificate has expired
     * @throws CertificateNotYetValidException
     *                 if the certificate is not valid yet.
     */
    public void checkValidity(Date date) throws CertificateExpiredException,
	    CertificateNotYetValidException {

	Calendar now = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
	now.setTime(date);

	if (now.before(tbsCertificate_.getNotBefore()))
	    throw new CertificateNotYetValidException(
		    "Certificate is not valid yet!");

	if (now.after(tbsCertificate_.getNotAfter()))
	    throw new CertificateExpiredException("Certificate is expired");

    }

    /**
     * Checks the validity period of this certificate against the given Calendar
     * instance.
     * 
     * @param now
     *                Calendar to be checked against the validity period of this
     *                certificate
     * @throws CertificateExpiredException
     *                 if the certificate has expired
     * @throws CertificateNotYetValidException
     *                 if the certificate is not valid yet.
     */
    public void checkValidity(Calendar now) throws CertificateExpiredException,
	    CertificateNotYetValidException {

	if (now.before(tbsCertificate_.getNotBefore()))
	    throw new CertificateNotYetValidException(
		    "Certificate is not valid yet");

	if (now.after(tbsCertificate_.getNotAfter()))
	    throw new CertificateExpiredException("Certificate is expired");

    }

    /**
     * From interface ASN1Type
     */
    public void decode(Decoder dec) throws ASN1Exception, IOException {
	Certificate_.decode(dec);
    }

    /**
     * From interface ASN1Type
     */
    public void encode(Encoder enc) throws ASN1Exception, IOException {
	Certificate_.encode(enc);
    }

    /**
     * From java.security.cert.X509Certificate. Returns the value of the
     * pathLenConstraint in a BC extension if present and cA set to true. If the
     * Basic Constraints extension (OID 2.5.29.19) is not present in this
     * certificate, null is returned.
     * 
     * <pre>
     * BasicConstraints ::= SEQUENCE {
     * cA                  BOOLEAN DEFAULT FALSE,
     *  pathLenConstraint   INTEGER (0..MAX) OPTIONAL
     * }
     * </pre>
     * 
     * @return the value of pathLenConstraint if present and cA set to true or
     *          null if the extension is not present
     */
    public int getBasicConstraints() {
	return tbsCertificate_.getBasicConstraints();
    }

    /**
     * From java.security.cert.X509Extension. Gets a set of Strings containing
     * all extension oids present being marked as critical.
     */
    public Set getCriticalExtensionOIDs() {
	return tbsCertificate_.getCriticalExtensionOIDs();
    }

    /**
     * returns the DER-encoded bytearray of this certificate
     */
    public byte[] getEncoded() throws CertificateEncodingException {
	byte[] res = null;

	ByteArrayOutputStream baos = new ByteArrayOutputStream();

	try {
	    encode(new DEREncoder(baos));
	    res = baos.toByteArray();
	    baos.close();
	} catch (IOException e) {
	    System.out.println("internal error:");
	    e.printStackTrace();
	} catch (ASN1Exception e) {
	    throw new CertificateEncodingException(e.getMessage());
	}
	return res;
    }

    /**
     * Returns a Collection containing all extensions
     */
    public Collection getExtensions() {
	return tbsCertificate_.getExtensions();
    }

    /**
     * From java.security.cert.X509Extension. Gets the value of the extensions
     * denoted by ex or null if not present.
     */
    public byte[] getExtensionValue(String ex) {
	return tbsCertificate_.getExtensionValue(ex);
    }

    /**
     * From java.security.cert.X509Certificate. Returns this certificate's
     * issuer as a Principal.
     */
    public java.security.Principal getIssuerDN() {
	return tbsCertificate_.getIssuerDN();
    }

    /**
     * From java.security.cert.X509Certificate. Returns the issuer's Unique ID
     * or null if not present.
     */
    public boolean[] getIssuerUniqueID() {
	return tbsCertificate_.getIssuerUniqueID();
    }

    /**
     * From java.security.cert.X509Certificate. Returns the bits of the KeyUsage
     * extension (OID 2.5.29.15) if present in this certificate or null
     * otherwise.
     * 
     * <pre>
     * KeyUsage ::= BIT STRING {
     *        digitalSignature        (0),
     *        nonRepudiation          (1),
     *        keyEncipherment         (2),
     *        dataEncipherment        (3),
     *        keyAgreement            (4),
     *        keyCertSign             (5),
     *        cRLSign                 (6),
     *        encipherOnly            (7),
     *        decipherOnly            (8)
     * }
     * </pre>
     * 
     * @return the key usage bits if present in this certificate, otherwise
     *          null.
     */
    public boolean[] getKeyUsage() {
	return tbsCertificate_.getKeyUsage();
    }

    /**
     * From java.security.cert.X509Extension. Gets a set of Strings containing
     * all extension oids present being marked as critical.
     */
    public Set getNonCriticalExtensionOIDs() {
	return tbsCertificate_.getNonCriticalExtensionOIDs();
    }

    /**
     * From java.security.cert.X509Certificate. Returns the Date after which
     * this certificate is not valid anymore.
     */
    public Date getNotAfter() {
	return tbsCertificate_.getNotAfter();
    }

    /**
     * From java.security.cert.X509Certificate. Returns the Date before which
     * this certificate is not valid.
     */
    public Date getNotBefore() {
	return tbsCertificate_.getNotBefore();
    }

    /**
     * From java.security.cert.X509Certificate. Returns the Public Key inside
     * this certificate
     */
    public java.security.PublicKey getPublicKey() {
	try {
	    return tbsCertificate_.getPublicKey();
	} catch (NoSuchAlgorithmException nsae) {
	    throw new IllegalStateException(
		    "Public Key algorithm not supported by any installed provider!");
	}
    }

    /**
     * From java.security.cert.X509Certificate. Returns the Serial Number of
     * this certificate
     */
    public BigInteger getSerialNumber() {
	return tbsCertificate_.getSerialNumber();
    }

    /**
     * From java.security.cert.X509Certificate. Returns the Java-compliant
     * Algorithm Name of the signature algorithm.
     */
    public String getSigAlgName() {
	String res = codec.util.JCA.getName(getSigAlgOID());

	// check if res == tbsCertificate_.getSigAlgName()!!

	return res;
    }

    /**
     * From java.security.cert.X509Certificate. Returns the Object Identifier
     * (OID) of the signature algorithm.
     */
    public String getSigAlgOID() {

	// check if res == tbsCertificate_.getSigAlgOID()!!

	return signatureAlgorithm_.getAlgorithmOID().toString();
    }

    /**
     * From java.security.cert.X509Certificate. Returns the Algorithm Parameters
     * for the signature algorithm in a DER encoded form.
     */
    public byte[] getSigAlgParams() {
	byte[] res = null;

	try {
	    res = signatureAlgorithm_.getParameters().getEncoded();
	} catch (Exception intern) {
	    System.out.println("internal Error:");
	    intern.printStackTrace();
	}

	return res;
    }

    /**
     * From java.security.cert.X509Certificate. Returns the signature of this
     * certificate.
     */
    public byte[] getSignature() {
	return signatureValue_.getBytes();
    }

    /**
     * From java.security.cert.X509Certificate. Returns this certificate's
     * subject as a Principal.
     */
    public java.security.Principal getSubjectDN() {
	return tbsCertificate_.getSubjectDN();
    }

    /**
     * From java.security.cert.X509Certificate. Returns the subject's Unique ID
     * or null if not present.
     */
    public boolean[] getSubjectUniqueID() {
	return tbsCertificate_.getSubjectUniqueID();
    }

    /**
     * From interface ASN1Type
     */
    public int getTag() {
	return Certificate_.getTag();
    }

    /**
     * From interface ASN1Type
     */
    public int getTagClass() {
	return Certificate_.getTagClass();
    }

    /**
     * From java.security.cert.X509Certificate. Returns the to-be-signed (TBS)
     * part of this certificate, meaning the byte-array that initializes the
     * signature algorithm. If you want to access methods or field inside
     * TBSCertificate, you should use
     * {@link #getX509TBSCertificate() getX509TBSCertificate} instead.
     */
    public byte[] getTBSCertificate() throws CertificateEncodingException {
	return tbsCertificate_.getEncoded();
    }

    /**
     * Returns tbe TBSCertificate Block as an Object. If you just want to get
     * the encoded TBSCertificate (in order to compute or verify a signature),
     * you should use {@link #getTBSCertificate() getTBSCertificate} instead.
     */
    public X509TBSCertificate getX509TBSCertificate() {
	return tbsCertificate_;
    }

    /**
     * Returns the to-be-signed (TBS) part of this certificate, meaning the
     * byte-array that initializes the signature algorithm. This method is
     * especially for issuing a certificate because the signature algorithm has
     * to be set to initialize correctly the TBS structure.
     * 
     * @param sigalg
     *                AlgorithmID of the signature algorithm or null (verify)
     * @throws CertificateEncodingException
     *                 if TBSCertificate could not be encoded
     */
    public byte[] getTBSCertificate(codec.x509.AlgorithmIdentifier sigalg)
	    throws CertificateEncodingException {
	tbsCertificate_.setSignatureAlgorithm(sigalg);
	setSignatureAlgorithm(sigalg);
	return tbsCertificate_.getEncoded();
    }

    /**
     * From interface ASN1Type
     */
    public Object getValue() {
	return Certificate_.getValue();
    }

    /**
     * Returns the version of this X509 certificate (0=v1, 1=v2, 2=v3)
     */
    public int getVersion() {
	return tbsCertificate_.getVersion();
    }

    /**
     * From java.security.cert.X509Extension. Returns true if this certificate
     * contains any extension being marked as critical but not supported by this
     * implementation.
     * <p>
     * Currently, this function will always return false since extensions are
     * managed in an abstract way.
     */
    public boolean hasUnsupportedCriticalExtension() {

	// Baustelle
	return false;
    }

    /**
     * From interface ASN1Type
     */
    public boolean isExplicit() {
	return Certificate_.isExplicit();
    }

    /**
     * From interface ASN1Type
     */
    public boolean isOptional() {
	return Certificate_.isOptional();
    }

    /**
     * From interface ASN1Type
     */
    public boolean isType(int eins, int zwei) {
	return Certificate_.isType(eins, zwei);
    }

    /**
     * From interface ASN1Type
     */
    public void setExplicit(boolean ex) {
	Certificate_.setExplicit(ex);
    }

    /**
     * Sets the TBS ("to-be-signed") part of this certificate. Note that no
     * cloning is done, so side effects may occur!
     */
    public void setTBSCertificate(X509TBSCertificate tbs) {
	tbsCertificate_ = tbs;
	Certificate_.set(0, tbsCertificate_);
    }

    /**
     * From interface ASN1Type
     */
    public void setOptional(boolean opt) {
	Certificate_.setOptional(opt);
    }

    /**
     * Sets the signature
     */
    public void setSignature(byte[] nsig) {
	try {
	    signatureValue_.setBits(nsig, 0);
	} catch (ConstraintException e) {
	    System.out.println("internal error:");
	    e.printStackTrace();
	}
    }

    /**
     * sets the signature algorithm
     * 
     * @param aid
     *                AlgorithmID of the signature algorithm
     */
    public void setSignatureAlgorithm(codec.x509.AlgorithmIdentifier aid) {

	signatureAlgorithm_ = (codec.x509.AlgorithmIdentifier) aid.clone();
	Certificate_.set(1, aid);

	tbsCertificate_
		.setSignatureAlgorithm((codec.x509.AlgorithmIdentifier) aid
			.clone());

    }

    /**
     * human-readable String representation of this certificate
     */
    public String toString() {
	String res;

	res = "X.509 Certificate {";
	res = res + tbsCertificate_.toString();

	res = res + "\nsignature:\n" + signatureValue_.toString();
	return res;
    }

    /**
     * with this method, the certificate can be verified in an easy, but less
     * secure way. If highest security is to be obtained,
     * {@link #getTBSCertificate() getTBSCertificate()} and
     * {@link #getSignature() getSignature()} should be used along with external
     * verification code.
     * 
     * @param key
     *                the issuer's public key to verify the TBS certificate
     */
    public void verify(PublicKey key)
	    throws java.security.cert.CertificateException,
	    NoSuchAlgorithmException, InvalidKeyException,
	    NoSuchProviderException, SignatureException {

	verify(key, "");
    }

    /**
     * with this method, the certificate can be verified in an easy, but less
     * secure way. If highest security is to be obtained,
     * {@link #getTBSCertificate() getTBSCertificate()} and
     * {@link #getSignature() getSignature()} should be used along with an
     * external verification.
     * 
     * @param key
     *                the issuer's public key to verify the TBS certificate
     * @param pro
     *                Provider to be used for signature mechanism
     */
    public void verify(PublicKey key, String pro)
	    throws java.security.cert.CertificateException,
	    NoSuchAlgorithmException, InvalidKeyException,
	    NoSuchProviderException, SignatureException {

	Signature theSig = null;
	String alg_name = getSigAlgName();
	String alg_oid = getSigAlgOID();

	// try to resolve Algorithm name first, then OID
	try {
	    if (pro != null && !pro.equals(""))
		theSig = Signature.getInstance(alg_name, pro);
	    else
		theSig = Signature.getInstance(alg_name);
	} catch (NoSuchAlgorithmException nsae) {
	    if (pro != null && !pro.equals(""))
		theSig = Signature.getInstance(alg_oid, pro);
	    else
		theSig = Signature.getInstance(alg_oid);
	}

	theSig.initVerify(key);
	theSig.update(getTBSCertificate());
	if (!theSig.verify(getSignature()))
	    throw new SignatureException("invalid Signature!");

    }

    /**
     * This methods implements an easy way to sign your certificate. Note that
     * TBSCertificate must be set before calling this method.
     * 
     * @param sig
     *                a Signature engine that is initialized for signing with
     *                the appropriate private key
     * @param signerPub
     *                the signer's public key
     * @throws SignatureException
     *                 if the signature could not be done
     * @throws CertificateEncodingException
     *                 if an error occured during tbsCertificate encoding
     * @throws NoSuchAlgorithmException
     *                 if the Public key or is not available signature algorithm
     * @throws InvalidAlgorithmParameterException
     *                 if signature algorithm parameters could not be encoded
     *                 correctly
     */
    public void sign(Signature sig, PublicKey signerPub)
	    throws SignatureException, CertificateEncodingException,
	    NoSuchAlgorithmException, InvalidAlgorithmParameterException {

	// extract signature parameters
	try {
	    AlgorithmIdentifier keyAlgID = AlgorithmIdentifier
		    .createAlgorithmIdentifier(signerPub);
	    AlgorithmParameters params = keyAlgID.getParameters();
	    AlgorithmIdentifier sigAlgID = new AlgorithmIdentifier(sig
		    .getAlgorithm(), params);

	    tbsCertificate_.setSignatureAlgorithm(sigAlgID);
	    setSignatureAlgorithm(sigAlgID);

	    sig.update(tbsCertificate_.getEncoded());
	    setSignature(sig.sign());
	} catch (CorruptedCodeException cce) {
	    throw new CertificateEncodingException(
		    "Cought CorruptedCodeException: " + cce.getMessage());
	}
    }

    /**
     * This methods implements an easy way to sign your certificate. Note that
     * TBSCertificate must be set before calling this method.
     * 
     * @param sig
     *                a Signature engine that is initialized for signing with
     *                the appropriate private key
     * @param cert
     *                the signer's signature certificate
     * @throws SignatureException
     *                 if the signature could not be done
     * @throws CertificateEncodingException
     *                 if an error occured during tbsCertificate encoding
     * @throws NoSuchAlgorithmException
     *                 if the Public key or is not available signature algorithm
     * @throws InvalidAlgorithmParameterException
     *                 if signature algorithm parameters could not be encoded
     *                 correctly
     */
    public void sign(Signature sig, java.security.cert.X509Certificate cert)
	    throws SignatureException, CertificateEncodingException,
	    NoSuchAlgorithmException, InvalidAlgorithmParameterException {
	sign(sig, cert.getPublicKey());
    }

    public void writeExternal(ObjectOutput s) throws IOException {
	byte[] res = null;

	ByteArrayOutputStream baos = new ByteArrayOutputStream();

	try {
	    encode(new DEREncoder(baos));
	    res = baos.toByteArray();
	    baos.close();
	    s.write(res);
	} catch (ASN1Exception e) {
	    throw new RuntimeException(e.toString());
	}
    }

    public void readExternal(ObjectInput s) throws IOException {
	try {
	    decode(new DERDecoder((ObjectInputStream) s));
	} catch (ASN1Exception e) {
	    throw new RuntimeException(e.toString());
	}
    }

}
