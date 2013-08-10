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
import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.math.BigInteger;
import java.security.cert.X509CRLEntry;
import java.text.DateFormat;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.TimeZone;

import codec.asn1.ASN1Choice;
import codec.asn1.ASN1Exception;
import codec.asn1.ASN1GeneralizedTime;
import codec.asn1.ASN1Integer;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1SequenceOf;
import codec.asn1.ASN1Time;
import codec.asn1.ASN1Type;
import codec.asn1.ASN1UTCTime;
import codec.asn1.Constraint;
import codec.asn1.ConstraintException;
import codec.asn1.DERDecoder;
import codec.asn1.DEREncoder;
import codec.asn1.Decoder;
import codec.asn1.Encoder;

/**
 * a CRLEntry is an entry in an {@link X509Crl X509Crl}. It consists of a
 * serial number, a date representation and optional extensions
 * 
 * <pre>
 * SEQUENCE  {
 *     userCertificate         CertificateSerialNumber,
 *     revocationDate          Time,
 *     crlEntryExtensions      Extensions OPTIONAL
 *                              -- if present, must be v2
 *  }
 * </pre>
 * 
 * Creation date: (10.09.99 19:03:34)
 * 
 * @author Markus Tak
 */
public class CRLEntry extends X509CRLEntry implements ASN1Type, Externalizable {

    private ASN1Sequence crlEntry_;

    private ASN1Integer userCertificate_;

    private ASN1Choice revocationDate_;

    private ASN1SequenceOf crlEntryExtensions_;

    /**
     * standard constructor; initializes the ASN.1 structure
     */
    public CRLEntry() {

	crlEntry_ = new ASN1Sequence();
	userCertificate_ = new ASN1Integer();

	crlEntry_.add(userCertificate_);

	revocationDate_ = new ASN1Choice();
	revocationDate_.addType(new ASN1UTCTime());
	revocationDate_.addType(new ASN1GeneralizedTime());

	crlEntry_.add(revocationDate_);

	crlEntryExtensions_ = new ASN1SequenceOf(X509Extension.class);
	crlEntryExtensions_.setOptional(true);
	crlEntry_.add(crlEntryExtensions_);
    }

    /**
     * constructor for a specific CRL entry
     */
    public CRLEntry(BigInteger nr, Calendar wann) {
	this();

	setSerialNumber(nr);
	setRevocationDate(wann);
    }

    /**
     * for interface {@link codec.asn1.ASN1Type codec.asn1.ASN1Type}
     */
    public void setConstraint(Constraint c) {
	crlEntry_.setConstraint(c);
    }

    /**
     * for interface {@link codec.asn1.ASN1Type codec.asn1.ASN1Type}
     */
    public Constraint getConstraint() {
	return crlEntry_.getConstraint();
    }

    /**
     * adds an extension to this CRLEntry
     */
    public void addExtension(X509Extension ex) {
	if (ex != null) {
	    crlEntryExtensions_.add(ex);
	    crlEntryExtensions_.setOptional(false);
	}
    }

    /**
     * for interface {@link codec.asn1.ASN1Type codec.asn1.ASN1Type}
     */
    public void checkConstraints() throws ConstraintException {
	crlEntry_.checkConstraints();
    }

    /**
     * for interface {@link codec.asn1.ASN1Type codec.asn1.ASN1Type}
     */
    public void decode(Decoder dec) throws ASN1Exception, IOException {
	crlEntry_.decode(dec);
    }

    /**
     * for interface {@link codec.asn1.ASN1Type codec.asn1.ASN1Type}
     */
    public void encode(Encoder enc) throws ASN1Exception, IOException {
	crlEntry_.encode(enc);
    }

    /**
     * implemented abstract method from
     * {@link java.security.cert.X509CRLEntry java.security.cert.X509CRLEntry}
     */
    public Set getCriticalExtensionOIDs() {
	HashSet res = new HashSet();

	Iterator it = crlEntryExtensions_.iterator();

	while (it.hasNext()) {
	    X509Extension theEx = (X509Extension) it.next();

	    if (theEx.isCritical()) {
		res.add(theEx.getOID().toString());
	    }
	}
	return res;
    }

    /**
     * implemented abstract method from
     * {@link java.security.cert.X509CRLEntry java.security.cert.X509CRLEntry}
     */
    public byte[] getEncoded() throws java.security.cert.CRLException {
	ByteArrayOutputStream baos = new ByteArrayOutputStream();

	try {
	    crlEntry_.encode(new DEREncoder(baos));
	} catch (Exception e) {
	    throw new java.security.cert.CRLException(e.getMessage());
	}

	return baos.toByteArray();
    }

    /**
     * implemented abstract method from
     * {@link java.security.cert.X509CRLEntry java.security.cert.X509CRLEntry}
     */
    public Collection getExtensions() {
	return crlEntryExtensions_.getCollection();
    }

    /**
     * implemented abstract method from
     * {@link java.security.cert.X509CRLEntry java.security.cert.X509CRLEntry}
     */
    public byte[] getExtensionValue(String oid) {
	byte[] res = null;

	Iterator it = crlEntryExtensions_.iterator();

	while (it.hasNext()) {
	    X509Extension theEx = (X509Extension) it.next();

	    if (theEx.getOID().toString().equals(oid)) {
		try {
		    ByteArrayOutputStream baos = new ByteArrayOutputStream();
		    theEx.encode(new DEREncoder(baos));
		    res = baos.toByteArray();
		} catch (Exception ignore) {
		}
	    }
	}
	return res;
    }

    /**
     * implemented abstract method from
     * {@link java.security.cert.X509CRLEntry java.security.cert.X509CRLEntry}
     */
    public Set getNonCriticalExtensionOIDs() {

	HashSet res = new HashSet();
	Iterator it = crlEntryExtensions_.iterator();

	while (it.hasNext()) {
	    X509Extension theEx = (X509Extension) it.next();

	    if (!theEx.isCritical()) {
		res.add(theEx.getOID().toString());
	    }
	}
	return res;
    }

    /**
     * implemented abstract method from
     * {@link java.security.cert.X509CRLEntry java.security.cert.X509CRLEntry}
     */
    public Date getRevocationDate() {
	ASN1Time a1t = (ASN1Time) revocationDate_.getInnerType();
	return a1t.getDate();
    }

    /**
     * implemented abstract method from
     * {@link java.security.cert.X509CRLEntry java.security.cert.X509CRLEntry}
     */
    public BigInteger getSerialNumber() {
	return userCertificate_.getBigInteger();
    }

    /**
     * for interface {@link codec.asn1.ASN1Type codec.asn1.ASN1Type}
     */
    public int getTag() {
	return crlEntry_.getTag();
    }

    /**
     * for interface {@link codec.asn1.ASN1Type codec.asn1.ASN1Type}
     */
    public int getTagClass() {
	return crlEntry_.getTagClass();
    }

    /**
     * for interface {@link codec.asn1.ASN1Type codec.asn1.ASN1Type}
     */
    public Object getValue() {
	return crlEntry_.getValue();
    }

    /**
     * implemented abstract method from
     * {@link java.security.cert.X509CRLEntry java.security.cert.X509CRLEntry}
     */
    public boolean hasExtensions() {
	return (!crlEntryExtensions_.isEmpty());
    }

    /**
     * implemented abstract method from
     * {@link java.security.cert.X509CRLEntry java.security.cert.X509CRLEntry}
     * 
     * @return always returns <code>false</code>
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
	return crlEntry_.isExplicit();
    }

    /**
     * for interface {@link codec.asn1.ASN1Type codec.asn1.ASN1Type}
     */
    public boolean isOptional() {
	return crlEntry_.isOptional();
    }

    /**
     * for interface {@link codec.asn1.ASN1Type codec.asn1.ASN1Type}
     */
    public boolean isType(int eins, int zwei) {
	return crlEntry_.isType(eins, zwei);
    }

    /**
     * for interface {@link codec.asn1.ASN1Type codec.asn1.ASN1Type}
     */
    public void setExplicit(boolean ex) {
	crlEntry_.setExplicit(ex);
    }

    /**
     * for interface {@link codec.asn1.ASN1Type codec.asn1.ASN1Type}
     */
    public void setOptional(boolean opt) {
	crlEntry_.setOptional(opt);
    }

    /**
     * set the date of this revocation entry
     */
    public void setRevocationDate(Calendar cal) {

	ASN1Time inner = (ASN1Time) revocationDate_.getInnerType();

	if (inner == null) {
	    inner = new ASN1UTCTime(cal);
	    revocationDate_.setInnerType(inner);
	}

	inner.setDate(cal);
    }

    /**
     * set the date of this revocation entry
     */
    public void setRevocationDate(Date date) {
	Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
	cal.setTime(date);
	setRevocationDate(cal);

    }

    /**
     * set the serial number date of the certificate to be revoked in this CRL
     * entry.
     */
    public void setSerialNumber(int nsnr) {
	setSerialNumber(new BigInteger(String.valueOf(nsnr), 10));
    }

    /**
     * set the serial number date of the certificate to be revoked in this CRL
     * entry.
     */
    public void setSerialNumber(BigInteger nsnr) {
	try {
	    userCertificate_.setBigInteger(nsnr);
	} catch (ASN1Exception ignore) {
	}
    }

    /**
     * menschl. lesbare Form
     */
    public String toString() {
	return toString("");
    }

    /**
     * menschl. lesbare Form
     */
    public String toString(String offset) {
	String res = offset + "SNR (dec):" + getSerialNumber().toString(10);

	String date = DateFormat.getDateTimeInstance(DateFormat.FULL,
		DateFormat.FULL).format(getRevocationDate());

	res = res + " date:" + date;

	if (!crlEntryExtensions_.isEmpty()) {
	    res = res + "\n" + offset + "extensions (";
	    res = res + crlEntryExtensions_.size() + "):";

	    for (int i = 0; i < crlEntryExtensions_.size(); i++) {
		res = res + "\n";
		res = res
			+ ((X509Extension) crlEntryExtensions_.get(i))
				.toString(offset + " ");
	    }
	}
	return res;
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
