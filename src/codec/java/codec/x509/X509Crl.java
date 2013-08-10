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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509CRL;
import java.text.DateFormat;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.TimeZone;

import codec.asn1.ASN1BitString;
import codec.asn1.ASN1Choice;
import codec.asn1.ASN1Exception;
import codec.asn1.ASN1GeneralizedTime;
import codec.asn1.ASN1Integer;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1SequenceOf;
import codec.asn1.ASN1TaggedType;
import codec.asn1.ASN1Time;
import codec.asn1.ASN1Type;
import codec.asn1.ASN1UTCTime;
import codec.asn1.Constraint;
import codec.asn1.ConstraintException;
import codec.asn1.DERDecoder;
import codec.asn1.DEREncoder;
import codec.asn1.Decoder;
import codec.asn1.Encoder;
import codec.x501.BadNameException;
import codec.x501.Name;

/**
 * Certificate Revocation List (CRL) according to rfc2459. It implements the
 * following ASN1 data structure:
 * <p>
 * 
 * <pre>
 * CertificateList  ::=  SEQUENCE  {
 * tbsCertList			TBSCertList,
 * signatureAlgorithm	AlgorithmIdentifier,
 * signature			BIT STRING
 * }
 * TBSCertList  ::=  SEQUENCE  {
 * 	version				Version OPTIONAL,
 * 						-- if present, must be v2
 * signature			AlgorithmIdentifier,
 * issuer				Name,
 * thisUpdate			Time,
 * nextUpdate			Time OPTIONAL,
 * revokedCertificates	SEQUENCE OF CRLEntry OPTIONAL,
 *  crlExtensions 		[0]  EXPLICIT Extensions OPTIONAL
 * 						-- if present, must be v2
 * }
 * </pre>
 * 
 * Creation date: (18.08.99 15:23:09)
 * 
 * @author Markus Tak
 */
public class X509Crl extends X509CRL implements ASN1Type {
    private ASN1Sequence CertificateList = null;
    private ASN1Sequence TBSCertList = null;
    private ASN1Integer version = null;
    private AlgorithmIdentifier signatureAlgorithm = null;
    private Name issuer = null;
    private ASN1Choice thisUpdate = null;
    private ASN1Choice nextUpdate = null;
    private ASN1SequenceOf revokedCertificates = null;
    private ASN1SequenceOf crlExtensions = null;
    private ASN1TaggedType crlExtensionsTag = null;
    private AlgorithmIdentifier signatureAlgorithm2 = null;
    private ASN1BitString signature = null;

    /**
     * constructor that builds the ASN.1 structure
     */
    public X509Crl() {

	CertificateList = new ASN1Sequence(3);
	TBSCertList = new ASN1Sequence(7);

	version = new ASN1Integer(1);
	/**/// BUGFIX: optional feld must be false if respective parameter is
	// set
	/**/
	version.setOptional(false);
	/**/// version.setOptional(true);
	/**/// XIFGUB: optional feld must be false if respective parameter is
	// set
	TBSCertList.add(version);

	signatureAlgorithm = new AlgorithmIdentifier();
	TBSCertList.add(signatureAlgorithm);

	issuer = new codec.x501.Name();
	TBSCertList.add(issuer);

	thisUpdate = new ASN1Choice();
	thisUpdate.addType(new ASN1UTCTime());
	thisUpdate.addType(new ASN1GeneralizedTime());
	TBSCertList.add(thisUpdate);

	nextUpdate = new ASN1Choice();
	nextUpdate.setOptional(true);
	nextUpdate.addType(new ASN1UTCTime());
	nextUpdate.addType(new ASN1GeneralizedTime());

	TBSCertList.add(nextUpdate);

	revokedCertificates = new ASN1SequenceOf(CRLEntry.class);
	revokedCertificates.setOptional(true);
	TBSCertList.add(revokedCertificates);

	crlExtensions = new ASN1SequenceOf(X509Extension.class);
	// ASN1TaggedType crl_ext = new ASN1TaggedType(0, crlExtensions, true,
	// true);
	// TBSCertList.add(crl_ext);
	crlExtensionsTag = new ASN1TaggedType(0, crlExtensions, true, true);
	TBSCertList.add(crlExtensionsTag);

	CertificateList.add(TBSCertList);

	signatureAlgorithm2 = new AlgorithmIdentifier();
	CertificateList.add(signatureAlgorithm);

	signature = new ASN1BitString();
	CertificateList.add(signature);

    }

    /**
     * Constructor upon Java objects. Takes an Name object (this crl's issuer)
     * and a Calendar object (date of this update)
     * 
     * @param issuer
     *                the issuer as a Name object
     * @param now
     *                time of the revocation
     */
    public X509Crl(codec.x501.Name issuer, Calendar now) {
	this();

	setIssuerDN(issuer);
	setThisUpdate(now);
    }

    /**
     * constructor that builds the ASN.1 structure
     */
    public X509Crl(int i) {

	CertificateList = new ASN1Sequence(3);
	TBSCertList = new ASN1Sequence(6);

	version = new ASN1Integer(1);
	/**/// BUGFIX: optional feld must be false if respective parameter is
	// set
	/**/
	version.setOptional(false);
	/**/// version.setOptional(true);
	/**/// XIFGUB: optional feld must be false if respective parameter is
	// set
	TBSCertList.add(version);

	signatureAlgorithm = new AlgorithmIdentifier();
	TBSCertList.add(signatureAlgorithm);

	issuer = new codec.x501.Name();
	TBSCertList.add(issuer);

	thisUpdate = new ASN1Choice();
	thisUpdate.addType(new ASN1UTCTime());
	thisUpdate.addType(new ASN1GeneralizedTime());
	TBSCertList.add(thisUpdate);

	/*
	 * nextUpdate = new ASN1Choice(); nextUpdate.setOptional(true);
	 * nextUpdate.addType(new ASN1UTCTime()); nextUpdate.addType(new
	 * ASN1GeneralizedTime());
	 * 
	 * TBSCertList.add(nextUpdate);
	 */
	revokedCertificates = new ASN1SequenceOf(CRLEntry.class);
	revokedCertificates.setOptional(true);
	TBSCertList.add(revokedCertificates);

	crlExtensions = new ASN1SequenceOf(X509Extension.class);
	// ASN1TaggedType crl_ext = new ASN1TaggedType(0, crlExtensions, true,
	// true);
	// TBSCertList.add(crl_ext);
	crlExtensionsTag = new ASN1TaggedType(0, crlExtensions, true, true);
	TBSCertList.add(crlExtensionsTag);

	CertificateList.add(TBSCertList);

	signatureAlgorithm2 = new AlgorithmIdentifier();
	CertificateList.add(signatureAlgorithm);

	signature = new ASN1BitString();
	CertificateList.add(signature);

    }

    public X509Crl(codec.x501.Name issuer, Calendar now, boolean _nextUpdate) {

	this(1);
	setIssuerDN(issuer);
	setThisUpdate(now);

    }

    /**
     * Constructor on an input stream that delivers the DER-encoded certificate
     * revocation list.
     */
    public X509Crl(InputStream is) throws ASN1Exception, IOException {
	this();
	this.decode(new DERDecoder(is));
    }

    /**
     * for interface {@link codec.asn1.ASN1Type codec.asn1.ASN1Type}
     */
    public void setConstraint(Constraint c) {
	CertificateList.setConstraint(c);
    }

    /**
     * for interface {@link codec.asn1.ASN1Type codec.asn1.ASN1Type}
     */
    public Constraint getConstraint() {
	return CertificateList.getConstraint();
    }

    /**
     * Adds a CRL entry. Note that this method marks the revokedCertificates
     * field as _NOT_ optional so that it will be encoded.
     * 
     * @param e
     *                a CRLEntry object that represents a revocation entry in
     *                this crl
     */
    public void addEntry(CRLEntry e) {
	revokedCertificates.add(e);
	revokedCertificates.setOptional(false);
    }

    /**
     * Adds a global extension to the CRL structure. This method assumes that
     * the version number of this instance is already v2(1), which is the case
     * by default. This should be kept in mind when changing, modifying, or
     * subclassing this implementation.
     * 
     * @param ex
     *                the X509 Extension to be added to the CRL (globally)
     */
    public void addExtension(X509Extension ex) {

	if (ex == null)
	    throw new NullPointerException("Extension is null!");
	System.out.println("CODEC : ADDING CRL EXTENSION");
	crlExtensions.add(ex);
	crlExtensionsTag.setOptional(false);

	/*
	 * Commented out the code below. Based on agreement, version numbers
	 * shall not be changed unless changed explicitly by a dedicated method
	 * call. --volker roth
	 */

	// try {
	// version.setBigInteger(new BigInteger("1"));
	// }
	// catch (ASN1Exception e) {
	// System.out.println("shouldnt happen:");
	// e.printStackTrace();
	// }
    }

    /**
     * for interface {@link codec.asn1.ASN1Type codec.asn1.ASN1Type}
     */
    public void checkConstraints() throws ConstraintException {
	CertificateList.checkConstraints();
    }

    /**
     * returns true if the given certificate serial number is revoked in this
     * CRL
     */
    public boolean containsCertificate(BigInteger s) {
	boolean res = false;

	Iterator it = revokedCertificates.iterator();
	while (it.hasNext() && !res) {
	    if (((CRLEntry) it.next()).getSerialNumber().equals(s))
		res = true;
	}

	return res;
    }

    /**
     * for interface {@link codec.asn1.ASN1Type codec.asn1.ASN1Type}
     */
    public void decode(Decoder dec) throws ASN1Exception, java.io.IOException {
	CertificateList.decode(dec);
    }

    /**
     * for interface {@link codec.asn1.ASN1Type codec.asn1.ASN1Type}
     */
    public void encode(Encoder enc) throws ASN1Exception, java.io.IOException {
	CertificateList.encode(enc);
    }

    /**
     * implementing abstract method in java.security.cert.X509CRL
     */
    public Set getCriticalExtensionOIDs() {

	HashSet res = new HashSet();

	Iterator it = crlExtensions.iterator();
	while (it.hasNext()) {
	    X509Extension theEx = (X509Extension) it.next();
	    if (theEx.isCritical())
		res.add(theEx.getOID().toString());
	}

	return res;
    }

    /**
     * implementing abstract method in java.security.cert.X509CRL
     */
    public byte[] getEncoded() throws java.security.cert.CRLException {

	java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();

	try {
	    CertificateList.encode(new DEREncoder(baos));
	} catch (Exception e) {
	    throw new java.security.cert.CRLException(e.getMessage());
	}

	return baos.toByteArray();
    }

    /**
     * returns a collection of all global extensions inside this crl
     */
    public Collection getExtensions() {
	return crlExtensions.getCollection();
    }

    /**
     * implementing abstract method in java.security.cert.X509CRL
     */
    public byte[] getExtensionValue(String ex) {
	byte[] res = null;

	Iterator it = crlExtensions.iterator();
	while (it.hasNext()) {

	    X509Extension theEx = (X509Extension) it.next();
	    if (theEx.getOID().toString().equals(ex)) {
		try {
		    ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
		    theEx.encode(new DEREncoder(baos));
		    res = baos.toByteArray();
		} catch (Exception ignore) {
		}
	    }

	}
	return res;
    }

    /**
     * implementing abstract method in java.security.cert.X509CRL
     */
    public Principal getIssuerDN() {
	return issuer;
    }

    /**
     * implementing abstract method in java.security.cert.X509CRL
     */
    public Date getNextUpdate() {

	if (nextUpdate.isOptional())
	    return null;

	ASN1Time a1t = (ASN1Time) nextUpdate.getInnerType();

	return a1t.getDate();
    }

    /**
     * implementing abstract method in java.security.cert.X509CRL
     */
    public Set getNonCriticalExtensionOIDs() {

	HashSet res = new HashSet();

	Iterator it = crlExtensions.iterator();
	while (it.hasNext()) {

	    X509Extension theEx = (X509Extension) it.next();
	    if (!theEx.isCritical())
		res.add(theEx.getOID().toString());

	}

	return res;
    }

    /**
     * implementing abstract method in java.security.cert.X509CRL
     */
    public java.security.cert.X509CRLEntry getRevokedCertificate(
	    BigInteger serialNumber) {

	CRLEntry res = null;

	Iterator it = revokedCertificates.iterator();
	while (it.hasNext() && res == null) {
	    CRLEntry cmp = (CRLEntry) it.next();
	    if (cmp.getSerialNumber().equals(serialNumber))
		res = cmp;
	}

	return res;

    }

    /**
     * implementing abstract method in java.security.cert.X509CRL
     */
    public Set getRevokedCertificates() {

	HashSet hs = new HashSet();

	Iterator it = revokedCertificates.iterator();

	while (it.hasNext()) {
	    CRLEntry ce = (CRLEntry) it.next();
	    hs.add(ce);
	}

	return hs;
    }

    /**
     * implementing abstract method in java.security.cert.X509CRL
     */
    public String getSigAlgName() {

	return codec.util.JCA.getName(getSigAlgOID());
    }

    /**
     * implementing abstract method in java.security.cert.X509CRL
     */
    public String getSigAlgOID() {
	return signatureAlgorithm.getAlgorithmOID().toString();
    }

    /**
     * implementing abstract method in java.security.cert.X509CRL
     */
    public byte[] getSigAlgParams() {

	try {
	    return signatureAlgorithm.getParameters().getEncoded();
	} catch (Exception e) {
	    return null;
	}

    }

    /**
     * implementing abstract method in java.security.cert.X509CRL
     */
    public byte[] getSignature() {
	return signature.getBytes();
    }

    /**
     * for interface {@link codec.asn1.ASN1Type codec.asn1.ASN1Type}
     */
    public int getTag() {
	return CertificateList.getTag();
    }

    /**
     * for interface {@link codec.asn1.ASN1Type codec.asn1.ASN1Type}
     */
    public int getTagClass() {
	return CertificateList.getTagClass();
    }

    /**
     * gets the binary to-be-signed which is the input for the java Signature
     * object for verifying
     * <p>
     * For signing use {@link #getTBSCertList(AlgorithmIdentifier)
     * getTBSCertList(AlgorithmIdentifier) }
     */
    public byte[] getTBSCertList() throws java.security.cert.CRLException {

	ByteArrayOutputStream baos = new ByteArrayOutputStream();
	try {
	    TBSCertList.encode(new DEREncoder(baos));
	} catch (Exception e) {
	    throw new java.security.cert.CRLException(e.getMessage());
	}

	return baos.toByteArray();

    }

    /**
     * gets the binary to-be-signed which is the input for the java Signature
     * object for signing
     * <p>
     * For verifying use {@link #getTBSCertList() getTBSCertList()}
     */
    public byte[] getTBSCertList(AlgorithmIdentifier sigalg)
	    throws java.security.cert.CRLException {

	setSignatureAlgorithm(sigalg);

	byte[] res = null;

	try {
	    res = getTBSCertList();
	} catch (Exception e) {
	    throw new java.security.cert.CRLException(e.getMessage());
	}

	return res;

    }

    /**
     * returns the issuing date of this crl update
     */
    public Date getThisUpdate() {
	ASN1Time a1t = (ASN1Time) thisUpdate.getInnerType();

	return a1t.getDate();
    }

    public Object getValue() {
	return CertificateList.getValue();
    }

    /**
     * returns the X.509 version (1,2) of this crl
     */
    public int getVersion() {
	return version.getBigInteger().intValue();
    }

    /**
     * implementing abstract method in java.security.cert.X509CRL
     * 
     * @return Always returns false
     */
    public boolean hasUnsupportedCriticalExtension() {
	boolean res = false;

	Set s = getCriticalExtensionOIDs();

	Iterator it = s.iterator();

	while (it.hasNext() && !res) {
	    it.next();

	    if (false)
		res = true;
	}

	return res;
    }

    /**
     * for interface {@link codec.asn1.ASN1Type codec.asn1.ASN1Type}
     */
    public boolean isExplicit() {
	return CertificateList.isExplicit();
    }

    /**
     * for interface {@link codec.asn1.ASN1Type codec.asn1.ASN1Type}
     */
    public boolean isOptional() {
	return CertificateList.isOptional();
    }

    /**
     * returns true if the given certificate is revoked in this crl
     */
    public boolean isRevoked(java.security.cert.Certificate crt) {
	boolean res = false;

	if (!(crt instanceof java.security.cert.X509Certificate))
	    return false;

	try {
	    BigInteger s = ((java.security.cert.X509Certificate) crt)
		    .getSerialNumber();

	    Iterator it = revokedCertificates.iterator();
	    while (it.hasNext() && !res) {
		if (((CRLEntry) it.next()).getSerialNumber().equals(s))
		    res = true;
	    }
	} catch (Exception i) {
	    res = true; // vorsichtshalber
	    System.out
		    .println("Hinweis: sicherheitshalber als revoziert betrachtet!");
	}

	return res;
    }

    /**
     * for interface {@link codec.asn1.ASN1Type codec.asn1.ASN1Type}
     */
    public boolean isType(int eins, int zwei) {
	return CertificateList.isType(eins, zwei);
    }

    /**
     * for interface {@link codec.asn1.ASN1Type codec.asn1.ASN1Type}
     */
    public void setExplicit(boolean ex) {
	CertificateList.setExplicit(ex);
    }

    /**
     * sets this issuer
     */
    public void setIssuerDN(Principal iss) {

	if (iss instanceof codec.x501.Name) {
	    issuer = (codec.x501.Name) iss;
	    TBSCertList.set(2, iss);
	} else {
	    try {
		issuer = new codec.x501.Name(iss.toString(), -1);
	    } catch (BadNameException e) {
		throw new RuntimeException("bad principal name:"
			+ e.getMessage());
	    }

	}

    }

    /**
     * sets the date of the next update
     */
    public void setNextUpdate(Calendar time) {

	/*
	 * nextUpdate = new ASN1Choice(); nextUpdate.setOptional(true);
	 * nextUpdate.addType(new ASN1UTCTime()); nextUpdate.addType(new
	 * ASN1GeneralizedTime());
	 * 
	 * TBSCertList.add(nextUpdate);
	 */

	ASN1Time akt_time = (ASN1Time) nextUpdate.getInnerType();
	if (akt_time == null) {
	    akt_time = new ASN1UTCTime(time);
	    nextUpdate.setInnerType(akt_time);
	}
	akt_time.setDate(time);
	nextUpdate.setOptional(false);
    }

    /**
     * sets the date of the next update Note that the TimeZone will be set to
     * GMT since Date objects do not support time zones.
     */
    public void setNextUpdate(Date time) {
	Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
	cal.setTime(time);
	setNextUpdate(cal);
    }

    /**
     * for interface {@link codec.asn1.ASN1Type codec.asn1.ASN1Type}
     */
    public void setOptional(boolean opt) {
	CertificateList.setOptional(opt);
    }

    /**
     * sets the signature on this object
     */
    public void setSignature(byte[] sig) {

	try {
	    signature.setBits(sig, 0);
	} catch (ConstraintException ignore) {
	}
    }

    /**
     * sets the signature algorithm for the signature private key
     */
    public void setSignatureAlgorithm(AlgorithmIdentifier sigalg) {
	signatureAlgorithm = sigalg;
	CertificateList.set(1, signatureAlgorithm);

	signatureAlgorithm2 = (AlgorithmIdentifier) sigalg.clone();
	TBSCertList.set(1, signatureAlgorithm2);
    }

    /**
     * sets the date of this update
     */
    public void setThisUpdate(Calendar time) {

	ASN1Time akt_time = (ASN1Time) thisUpdate.getInnerType();
	if (akt_time == null) {
	    akt_time = new ASN1UTCTime(time);
	    thisUpdate.setInnerType(akt_time);
	}

	akt_time.setDate(time);
    }

    /**
     * sets the date of this update Note that the TimeZone will be set to GMT
     * since Date objects do not support time zones.
     */
    public void setThisUpdate(Date time) {
	Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
	cal.setTime(time);
	setThisUpdate(cal);
    }

    /**
     * Returns a human-readable string representation of this certificate
     * revocation list
     */
    public String toString() {
	return toString("");

    }

    /**
     * Returns a human-readable string representation of this certificate
     * revocation list
     */
    public String toString(String offset) {
	String res = "";

	res = offset + "X.509 Certificate Revocation List (V";
	res = res + (version.getBigInteger().intValue() + 1) + "):";
	res = res + "\n" + offset + "issuer:" + getIssuerDN().toString();

	String thisupd = DateFormat.getDateTimeInstance(DateFormat.FULL,
		DateFormat.FULL).format(getThisUpdate());
	res = res + "\n" + offset + "this update:" + thisupd;

	if (!nextUpdate.isOptional()) {
	    String nextupd = DateFormat.getDateTimeInstance(DateFormat.FULL,
		    DateFormat.FULL).format(getNextUpdate());
	    res = res + "\n" + offset + "next update:" + nextupd;
	}

	if (revokedCertificates.isEmpty())
	    res = res + "\n" + offset + "no revoked certificates.";
	else {
	    res = res + "\n" + offset + "revoked certificates:";

	    int i = 1;
	    Iterator it = revokedCertificates.iterator();
	    while (it.hasNext()) {
		CRLEntry ent = (CRLEntry) it.next();
		res = res + "\n" + offset + String.valueOf(i) + ":";
		res = res + ent.toString(offset + "  ");
		i++;
	    }
	}

	if (!crlExtensions.isEmpty()) {
	    res = res + "\n" + offset + "CRL Extensions:";
	    Iterator it = crlExtensions.iterator();
	    while (it.hasNext()) {
		X509Extension ext = (X509Extension) it.next();
		res = res + "\n" + ext.toString(offset + " ");
	    }

	}

	res = res + "\n" + offset + "signature algorithm:" + getSigAlgName();
	res = res + "\n" + offset + "signature:" + signature.toString();

	return res;
    }

    /**
     * With this method, the certificate can be verified in an easy, but less
     * secure way. If highest security is to be obtained, {link
     * #getTBSCertList() getTBSCertList()} and {link #getSignature()
     * getSignature()} should be used along with an external verification
     * routine.
     * 
     * @param key
     *                the issuer's public key to verify the TBS certlist
     * @throws NoSuchAlgorithmException
     *                 If there is no appropriate provider
     * @throws InvalidKeyException
     *                 If there is a problem with the public key
     * @throws SignatureException
     *                 If the Signature was bad.
     */
    public void verify(java.security.PublicKey key)
	    throws java.security.cert.CRLException, NoSuchAlgorithmException,
	    InvalidKeyException, NoSuchProviderException, SignatureException {
	verify(key, "");
    }

    /**
     * with this method, the certificate can be verified in an easy, but less
     * secure way. If highest security is to be obtained, {link
     * #getTBSCertList() getTBSCertList()} and {link #getSignature()
     * getSignature()} should be used along with an external verification
     * routine.
     * 
     * @param key
     *                the issuer's public key to verify the TBS certlist
     * @param sigProvider
     *                a preferred JCA provider to be used for verification
     * 
     * @throws NoSuchAlgorithmException
     *                 If there is no appropriate provider
     * @throws NoSuchProviderException
     *                 If the given provider could not be found
     * @throws InvalidKeyException
     *                 If there is a problem with the public key
     * @throws SignatureException
     *                 If the Signature was bad.
     */
    public void verify(java.security.PublicKey key, String sigProvider)
	    throws java.security.cert.CRLException, NoSuchAlgorithmException,
	    InvalidKeyException, NoSuchProviderException, SignatureException {

	Signature theSig = null;
	String alg_oid = getSigAlgOID();
	String alg_name = getSigAlgName();

	// try to find the algorithm
	try {
	    if (!sigProvider.equals(""))
		theSig = Signature.getInstance(alg_name, sigProvider);
	    else
		theSig = Signature.getInstance(alg_name);
	} catch (NoSuchAlgorithmException nsae) {
	    if (!sigProvider.equals(""))
		theSig = Signature.getInstance(alg_oid, sigProvider);
	    else
		theSig = Signature.getInstance(alg_oid);
	}

	theSig.initVerify(key);
	theSig.update(getTBSCertList());
	if (!theSig.verify(getSignature()))
	    throw new SignatureException("Invalid Signature!");

    }

}
