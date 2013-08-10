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
import java.security.cert.CertificateEncodingException;
import java.util.HashSet;
import java.util.Set;

import codec.asn1.ASN1Boolean;
import codec.asn1.ASN1Exception;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1OctetString;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1Type;
import codec.asn1.ConstraintException;
import codec.asn1.DERDecoder;
import codec.asn1.DEREncoder;

/**
 * This class represents an X.509 extension of this form
 * <p>
 * 
 * <pre>
 * Extension  ::=  SEQUENCE  {
 *  extnID      OBJECT IDENTIFIER,
 *  critical    BOOLEAN DEFAULT FALSE,
 *  extnValue   OCTET STRING
 * }
 * </pre>
 * 
 * Creation date: (18.08.99 15:23:09)
 * 
 * @author Markus Tak
 */
public class X509Extension extends ASN1Sequence implements
	java.security.cert.X509Extension, Externalizable {

    protected ASN1ObjectIdentifier extnID = null;
    protected ASN1Boolean critical = null;
    protected ASN1OctetString extnValue = null;

    /**
     * Creates an instance ready for use in decoding extensions.
     */
    public X509Extension() {
	/*
	 * If used for decoding, ASN.1 objects do not need special
	 * initialization values. On the contrary, ASN.1 objects generally
	 * initialize for decoding when the default constructor is invoked.
	 * --volker roth
	 */
	extnID = new ASN1ObjectIdentifier();
	add(extnID);

	critical = new ASN1Boolean(false);
	critical.setOptional(true);

	add(critical);

	extnValue = new ASN1OctetString();
	add(extnValue);
    }

    /**
     * Initializes this extension from the given DER code.
     * 
     * @param b
     *                The DER code.
     * @throws ASN1Exception
     *                 iff the data cannot be decoded correctly.
     */
    public X509Extension(byte[] b) throws ASN1Exception, IOException {
	this();

	/*
	 * This method need not declare or throw an IOException. It would be
	 * better to just catch it and throw a runtime exception (an error).
	 * 
	 * --volker roth
	 */
	ByteArrayInputStream in;
	DERDecoder dec;

	if (b == null) {
	    throw new NullPointerException("input array");
	}
	in = new ByteArrayInputStream(b);
	dec = new DERDecoder(in);

	decode(dec);

	/*
	 * Let stream free resources.
	 */
	in.close();
    }

    /**
     * This constructor fills-up the data structure.
     * 
     * @param theoid
     *                This extension's OID
     * @param crit
     *                TRUE if this extension shall be critical
     * @param val
     *                The value of this extension as a ASN1Type. This one will
     *                be DER-encoded and be put into an ASN1OctetString
     */
    public X509Extension(ASN1ObjectIdentifier theoid, boolean crit, ASN1Type val)
	    throws Exception {
	this();

	this.setOID(theoid);
	this.setCritical(crit);
	this.setValue(val);
    }

    /**
     * From interface java.security.cert.X509Extension.
     * 
     * @return either an empty Set if this extension is not critical or a Set
     *          containing one element (this extension's OID) if this extension
     *          is marked as critical.
     */
    public Set getCriticalExtensionOIDs() {

	HashSet res = new HashSet();

	if (isCritical())
	    res.add(getOID());

	return res;
    }

    /**
     * Returns the DER encoding of this extension. From
     * java.security.cert.X509Extension
     * 
     * @return a byte array containing the DER-encoding of this extension
     */
    public byte[] getEncoded() throws CertificateEncodingException {
	ByteArrayOutputStream bos = new ByteArrayOutputStream();
	DEREncoder enc = new DEREncoder(bos);

	try {
	    this.encode(enc);
	    bos.close();
	} catch (IOException e) {
	    System.err.println("getenc Internal error: shouldn't happen!");
	    e.printStackTrace();
	} catch (ASN1Exception e) {
	    throw new CertificateEncodingException(e.getMessage());
	}
	return bos.toByteArray();

    }

    /**
     * From java.security.cert.X509Extension. Returns the DER encoding of this
     * extension if the given OID matches
     * 
     * @param oid
     *                the OID to search for
     * @return a byte array containing the DER-encoding of this extension
     */
    public byte[] getExtensionValue(String oid) {
	byte[] res = null;

	if (extnValue == null)
	    return null;

	if (extnID.toString().equals(oid)
		|| extnID.toString().equals(new String("OID." + oid))) {

	    // res = extnValue.getByteArray();

	    try {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DEREncoder enc = new DEREncoder(baos);
		extnValue.encode(enc);
		res = baos.toByteArray();
		baos.close();
	    } catch (ASN1Exception asn1e) {
		throw new IllegalStateException(
			"Caught ASN1Exception. Internal Error. Shouldn't happen");
	    } catch (IOException ioe) {
		throw new IllegalStateException(
			"Internal Error. Shouldn't happen");
	    }

	}
	return res;
    }

    public Set getNonCriticalExtensionOIDs() {

	HashSet res = new HashSet();

	if (!isCritical())
	    res.add(getOID());

	return res;

    }

    /**
     * Returns the OID of this extension
     * 
     * @return This extension's OID
     */
    public ASN1ObjectIdentifier getOID() {
	return extnID;
    }

    /**
     * Returns this extension's value. The value is tried to be decoded and
     * returned as a ASN1Type object. If decoding fails for some reason (e.g.
     * extension did not contain a DER encoded ASN.1 type, the ASN1OctetString
     * containing the original value is returned.
     */
    public Object getValue() {
	ByteArrayInputStream bis;
	DERDecoder dec;
	ASN1Type res = null;

	try {
	    bis = new ByteArrayInputStream(extnValue.getByteArray());
	    dec = new DERDecoder(bis);
	    res = dec.readType();
	    dec.close();
	} catch (IOException e) {
	    System.err.println("Internal error: shouldn't happen!");
	    e.printStackTrace();
	} catch (ASN1Exception e) {
	    res = extnValue;
	}
	return res;

    }

    /**
     * This method allows to decode the extension value based on an ASN.1
     * template. This implicitly checks the syntax of the decoded type.
     */
    protected void decodeExtensionValue(ASN1Type t) throws ASN1Exception,
	    IOException {
	ByteArrayInputStream bis;
	DERDecoder dec;

	if (t == null) {
	    throw new NullPointerException("input parameter");
	}
	bis = new ByteArrayInputStream(extnValue.getByteArray());
	dec = new DERDecoder(bis);

	t.decode(dec);
	dec.close();
    }

    /**
     * From java.security.cert.X509Extension
     * 
     * @return always false
     */
    public boolean hasUnsupportedCriticalExtension() {

	if (!isCritical())
	    return false;
	return false;
    }

    /**
     * Returns the critical flag of this extension
     * 
     * @return true if this extension is marked as critical
     */
    public boolean isCritical() {
	if (isOptional())
	    return false;
	return critical.isTrue();
    }

    /**
     * Set the critical of this extension
     * 
     * @param ncrit
     *                true if this extension shall be marked critical
     */
    public void setCritical(boolean ncrit) {

	if (!ncrit)
	    critical.setOptional(true);
	else {
	    critical.setTrue(ncrit);
	    critical.setOptional(false);
	}
    }

    /**
     * Set this extension's OID
     * 
     * @param noid
     *                this extension's new OID
     */
    public void setOID(ASN1ObjectIdentifier noid) throws ConstraintException {
	extnID.setOID(noid.getOID());
    }

    /**
     * Set this extension's value
     * 
     * @param nval
     *                the new value of this extension. Note that this value will
     *                be DER-encoded and stored inside an ASN1OctetString
     * @throws CertificateEncodingException
     *                 if encoding fails
     */
    public void setValue(ASN1Type nval) throws CertificateEncodingException {
	ByteArrayOutputStream baos = new ByteArrayOutputStream();

	try {
	    nval.encode(new DEREncoder(baos));
	    extnValue.setByteArray(baos.toByteArray());
	} catch (Exception e) {
	    throw new CertificateEncodingException(e.getMessage());
	}
    }

    /**
     * Returns a human-readable String representation of this extension
     */
    public String toString() {
	return toString("");

    }

    /**
     * Returns a human-readable String representation of this extension with an
     * offset String.
     * 
     * @param offset
     *                String that will be put before each line of output
     */
    public String toString(String offset) {
	String res = offset;

	res = "Extension " + extnID.toString();

	if (critical.isTrue())
	    res = res + " (CRITICAL)";
	else
	    res = res + " (not critical)";

	res = res + " Value=" + getValue().toString();

	return res;
    }

}
