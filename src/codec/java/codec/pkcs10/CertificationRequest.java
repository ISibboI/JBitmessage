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
package codec.pkcs10;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import codec.CorruptedCodeException;
import codec.InconsistentStateException;
import codec.asn1.ASN1BitString;
import codec.asn1.ASN1Exception;
import codec.asn1.ASN1Integer;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1Set;
import codec.asn1.ASN1SetOf;
import codec.asn1.ASN1TaggedType;
import codec.asn1.ConstraintException;
import codec.asn1.DERDecoder;
import codec.asn1.DEREncoder;
import codec.x501.Attribute;
import codec.x501.Name;
import codec.x509.AlgorithmIdentifier;
import codec.x509.SubjectPublicKeyInfo;

/**
 * PKCS#10 Certification Request. This Object can be used to build a PKCS#10
 * compliant certification request for a self-created public key pair. The
 * public key and the name of the subject have to be put into this certification
 * request that is to be sent to a certification authority for certificate
 * generation.
 * <p>
 * PKCS#10 defines the following data structure for certificate requests:
 * 
 * <pre>
 * CertificationRequest ::= SEQUENCE {
 * certificationRequestInfo   CertificationRequestInfo,
 * signatureAlgorithm         AlgorithmIdentifier,
 * signature                  BIT STRING
 * }
 * CertificationRequestInfo ::= SEQUENCE {
 * version                    Integer,
 * subject                    Name,
 * subjectPublicKeyInfo       SubjectPublicKeyInfo,
 * attributes                 [0] IMPLICIT Attributes
 * }
 * Attributes ::= SET OF Attribute -- see PKCS#9
 * </pre>
 * 
 * To build a PKCS#10 certification request, you can use the constructor {@link
 * #CertificationRequest(PublicKey,Name)} with your public key and name. After
 * that, you have to call {@link #getTBS()} to get the to-be-signed (tbs) data,
 * sign them outside and call {@link #setSignature(byte[], AlgorithmIdentifier)}
 * to fill-in the signature data. After that, you can export the certification
 * request using {@link #getEncoded getEncoded()}.
 * 
 * Creation date: (18.08.99 15:23:09)
 * 
 * @author Markus Tak Update: (20.05.00 15:23:09)
 * @author Markus Ruppert
 */
public class CertificationRequest extends ASN1Sequence {

    private ASN1Sequence certificationRequestInfo_ = null;
    private ASN1Integer version_ = null;
    private Name subject_ = null;
    private SubjectPublicKeyInfo subjectPublicKeyInfo_ = null;
    private ASN1Set attributes_ = null;
    private AlgorithmIdentifier signatureAlgorithmIdentifier_ = null;
    private ASN1BitString signature_ = null;

    /**
     * Structure-constructor that builds the ASN.1 data structure. Creation
     * date: (20.08.99 21:42:03)
     */
    public CertificationRequest() {

	super(3);

	certificationRequestInfo_ = new ASN1Sequence();

	version_ = new ASN1Integer(0);
	certificationRequestInfo_.add(version_);

	subject_ = new Name();
	certificationRequestInfo_.add(subject_);

	subjectPublicKeyInfo_ = new SubjectPublicKeyInfo();
	certificationRequestInfo_.add(subjectPublicKeyInfo_);

	attributes_ = new ASN1SetOf(Attribute.class);
	certificationRequestInfo_.add(new ASN1TaggedType(0, attributes_, false,
		false));

	add(certificationRequestInfo_);

	signatureAlgorithmIdentifier_ = new AlgorithmIdentifier();
	add(signatureAlgorithmIdentifier_);

	signature_ = new ASN1BitString();
	add(signature_);
    }

    /**
     * Constructor upon an byte-array that holds the DER-encoded Certification
     * Request.
     * 
     * Creation date: (20.08.99 21:42:03)
     */
    public CertificationRequest(byte[] enc) throws ASN1Exception {
	this();

	try {
	    ByteArrayInputStream bais = new ByteArrayInputStream(enc);

	    decode(new DERDecoder(bais));
	    bais.close();
	} catch (IOException e) {
	    throw new ASN1Exception(e.getMessage());
	}
    }

    /**
     * Constructor upon an input stream. The stream is closed by this
     * constructor.
     * 
     * @param in
     *                InputStream that delivers the DER-encoded PKCS#10
     *                Certification Request
     * 
     * Creation date: (20.08.99 21:42:03)
     */
    public CertificationRequest(InputStream in) throws ASN1Exception,
	    IOException {
	this();

	DERDecoder dec;

	dec = new DERDecoder(in);
	decode(dec);
	dec.close();
    }

    /**
     * The given public key and name objects are put into this certification
     * request. After that, you have to call {@link #getTBS()} to get the
     * to-be-signed (tbs) data, sign them outside and call {@link
     * #setSignature(byte[], AlgorithmIdentifier)} to fill-in the signature
     * data. After that, you can export the certification request using
     * {@link #getEncoded()}.
     * 
     * @param pk
     *                the public key that is to be put inside this certification
     *                request
     * @param sub
     *                the Subject's name
     * 
     * Creation date: (20.08.99 21:42:03)
     */
    public CertificationRequest(PublicKey pk, Name sub)
	    throws InvalidKeyException {
	this();

	setPublicKey(pk);
	setSubjectDN(sub);
    }

    /**
     * Standard-constructor upon JAVA-Objects. The given public key and name
     * objects are put into this certification request. After that, you have to
     * call {@link #getTBS()} to get the to-be-signed (tbs) data, sign them
     * outside and call {@link #setSignature(byte[], AlgorithmIdentifier)} to *
     * fill-in the signature data. After that, you can export the certification
     * request using {@link #getEncoded()}.
     * 
     * @param pk
     *                the public key that is to be put inside this certification
     *                request
     * @param sub
     *                the Subject's name
     * @param attr
     *                the Subject's attributes
     * 
     * Creation date: (20.05.00 18:46:46)
     */
    public CertificationRequest(PublicKey pk, Name sub, Collection attr)
	    throws InvalidKeyException {
	this();

	setPublicKey(pk);
	setSubjectDN(sub);
	setAttributes(attr);
    }

    /**
     * Returns an unmodifiable list view on the attributes.
     * 
     * Creation date: (20.05.00 18:46:46)
     * 
     * @return The attributes
     */
    public List getAttributes() {
	return Collections.unmodifiableList(attributes_);
    }

    /**
     * Returns the DER-encoded PKCS#10 data structure.
     * 
     * @throws ASN1Exception
     *                 if an encoding problem occurs
     */
    public byte[] getEncoded() throws ASN1Exception {
	byte[] res;

	try {
	    ByteArrayOutputStream baos = new ByteArrayOutputStream();

	    encode(new DEREncoder(baos));
	    res = baos.toByteArray();
	    baos.close();
	} catch (IOException e) {
	    throw new ASN1Exception(e.getMessage());
	}
	return res;

    }

    /**
     * Returns the public key inside this Certification Request.
     * 
     * Creation date: (20.08.99 21:42:03)
     */
    public PublicKey getPublicKey() throws NoSuchAlgorithmException {
	return subjectPublicKeyInfo_.getPublicKey();
    }

    /**
     * Returns the AlgorithmIdentifier describing the public key's algorithm.
     * 
     * Creation date: (20.08.99 21:42:03)
     */
    public AlgorithmIdentifier getPublicKeyAlgorithm() {
	return subjectPublicKeyInfo_.getAlgorithmIdentifier();
    }

    /**
     * Returns the signature on this certification request that is done by
     * appliying the corresponding private key.
     * 
     * Creation date: (20.08.99 21:42:03)
     */
    public byte[] getSignature() {

	return signature_.getBytes();
    }

    /**
     * Returns the subject's distinguished name.
     * 
     * Creation date: (20.08.99 21:42:03)
     */
    public Name getSubjectDN() {
	return subject_;
    }

    /**
     * Returns the to-be-signed (TBS) data structure, meaning the data to be
     * applied on the signature algorithm. This method has to be called for
     * verifying the signature.
     * 
     * Creation date: (20.08.99 21:42:03)
     */
    public byte[] getTBS() throws CorruptedCodeException {
	byte[] res;

	try {
	    ByteArrayOutputStream baos = new ByteArrayOutputStream();

	    certificationRequestInfo_.encode(new DEREncoder(baos));
	    res = baos.toByteArray();
	    baos.close();
	} catch (IOException e) {
	    throw new CorruptedCodeException("internal error: "
		    + e.getMessage());
	} catch (ASN1Exception e) {
	    throw new CorruptedCodeException(e.getMessage());
	}

	return res;

    }

    /**
     * Sets the given attributes.
     * 
     * @param attributes
     *                The attributes.
     * 
     * Creation date: (20.05.00 18:46:46)
     */
    public void setAttributes(Collection attributes) {
	if (attributes == null) {
	    throw new NullPointerException("Attributes instance is null!");
	}
	attributes_.clear();
	attributes_.addAll(attributes);
    }

    /**
     * Sets the public key.
     * 
     * @param pk
     *                the public key to be put into this certification request
     *                Creation date: (20.08.99 21:42:03)
     */
    private void setPublicKey(PublicKey pk) throws InvalidKeyException {

	subjectPublicKeyInfo_ = new SubjectPublicKeyInfo(pk);
	certificationRequestInfo_.set(2, subjectPublicKeyInfo_);

    }

    /**
     * Sets the signature. Can only be called after {@link #getTBS()}. Note
     * that the AlgorithmIdentifier <code>algID</code> is not copied, meaning
     * that after calling this method, it must not be changed. Otherwise the
     * validity of the signature is lost and the object contents are corrupted!
     * 
     * @param sg
     *                the new signature
     * @param algID
     *                the algorithm identifier that describes the signature
     *                algorithm Creation date: (20.08.99 21:42:03)
     */
    public void setSignature(byte[] sg, AlgorithmIdentifier algID) {

	try {
	    signature_.setBits(sg, 0);

	    signatureAlgorithmIdentifier_ = algID;
	    set(1, signatureAlgorithmIdentifier_);
	} catch (ConstraintException ignore) {
	}
    }

    /**
     * Sets the subject's distinguished name (DN).
     * 
     * @param sub
     *                the distinguished name Creation date: (20.08.99 21:42:03)
     */
    private void setSubjectDN(Name sub) {

	subject_ = sub;
	certificationRequestInfo_.set(1, sub);
    }

    /**
     * Human-readable string representation of this Certification Request.
     * Creation date: (20.08.99 21:44:32)
     * 
     * @return java.lang.String
     */
    public String toString() {
	String res = "";

	res = "PKCS#10 Certification Request:";
	res = res + "\nSubject: " + subject_.toString();
	res = res + "\nAlgorithm: "
		+ subjectPublicKeyInfo_.getAlgorithmIdentifier();
	res = res + "\nKey: ";

	try {
	    res = res + subjectPublicKeyInfo_.getPublicKey().toString();
	} catch (NoSuchAlgorithmException e) {
	    res = res + "Key algorithm not supported!";
	} catch (InconsistentStateException e) {
	    res = res + "Key data corrupted!";
	}
	res = res + "\nAttributes: " + attributes_.size() + "elements \n";

	return res;
    }

    /**
     * With this method, the certification request can be verified in an easy,
     * but less secure way. If highest security is to be obtained,
     * {@link #getTBS()}, {@link #getPublicKey()} and {@link #getSignature()}
     * should be used along with an external verification. Verification is
     * successful if the signature can be verified using the public key inside
     * this object. Successful verification is done if no exception is thrown
     * from this method.
     */
    public void verify() throws NoSuchAlgorithmException, InvalidKeyException,
	    NoSuchProviderException, SignatureException {

	verify("");

    }

    /**
     * With this method, the certification request can be verified in an easy,
     * but less secure way. If highest security is to be obtained,
     * {@link #getTBS()}, {@link #getPublicKey()} and {@link #getSignature()}
     * should be used along with an external verification. Verification is
     * successful if the signature can be verified using the public key inside
     * this object. Successful verification is done if no exception is thrown
     * from this method.
     * 
     * @param pro
     *                Provider to be used for signature mechanism
     */
    public void verify(String pro) throws NoSuchAlgorithmException,
	    InvalidKeyException, NoSuchProviderException, SignatureException {

	Signature theSig = null;
	String alg_name = signatureAlgorithmIdentifier_.getAlgorithmName();
	String alg_oid = signatureAlgorithmIdentifier_.getAlgorithmOID()
		.toString();

	try {
	    if (pro != null && !pro.equals("")) {
		theSig = Signature.getInstance(alg_name, pro);
	    } else {
		theSig = Signature.getInstance(alg_name);
	    }
	} catch (NoSuchAlgorithmException nsae) {
	    if (pro != null && !pro.equals("")) {
		theSig = Signature.getInstance(alg_oid, pro);
	    } else {
		theSig = Signature.getInstance(alg_oid);
	    }
	}

	try {
	    PublicKey thePubKey = getPublicKey();

	    theSig.initVerify(thePubKey);
	    theSig.update(getTBS());
	    if (!theSig.verify(getSignature())) {
		throw new SignatureException("invalid Signature!");
	    }
	} catch (CorruptedCodeException e) {
	    throw new InvalidKeyException("Key material could not be obtained");
	}
    }

    /**
     * This methods implements an easy way to sign your certificate request.
     * 
     * @param sig
     *                a Signature engine that is initialized for signing with
     *                the appropriate private key
     * @param signerPub
     *                the signer's public key (it is required to extract
     *                algorithm parameters)
     * 
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

	    sig.update(getTBS());
	    setSignature(sig.sign(), sigAlgID);
	} catch (CorruptedCodeException cce) {
	    throw new java.security.cert.CertificateEncodingException(
		    "Caught CorruptedCodeException: " + cce.getMessage());
	}
    }
}