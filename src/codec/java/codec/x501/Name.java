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
package codec.x501;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.Vector;

import codec.asn1.ASN1;
import codec.asn1.ASN1Exception;
import codec.asn1.ASN1IA5String;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1OpenType;
import codec.asn1.ASN1PrintableString;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1SequenceOf;
import codec.asn1.ASN1Set;
import codec.asn1.ASN1SetOf;
import codec.asn1.ASN1String;
import codec.asn1.ASN1T61String;
import codec.asn1.ASN1Type;
import codec.asn1.ASN1UTF8String;
import codec.asn1.BERDecoder;
import codec.asn1.DEREncoder;
import codec.asn1.Decoder;
import codec.asn1.Resolver;

/**
 * This class represents the X501 Name. A Name is used to identify people or
 * organizations. It must be written as a RFC2253 string. For example:
 * 
 * <pre>
 *  CN=Steve Kille, O=ISODE Consortium, C=GB
 * </pre>
 * 
 * With this Name an ASN1Structure as defined in <a
 * href="ftp://ftp.rsa.com/pub/pkcs/ascii/layman.asc"> Layman's Guide to ASN.1</a>
 * is build.
 * <p>
 * 
 * The Principal interface method {@link #getName getName} returns the encoded
 * name in little-endian format in accordance with <a
 * href="ftp://ftp.rfc-editor.org/in-notes/rfc2253.txt">RFC2253</a> and the
 * IANA assigned numbers document for <a
 * href="http://www.iana.org/assignments/directory-system-names"> Directory
 * System Names</a>.
 * <p>
 * 
 * If the Name is initalised with a RFC2253 conformant syntax then the
 * attributes are encoded in the opposite order they appear in the name(in
 * little-endian order).
 * <p>
 * 
 * If the Name is initialized by decoding a DER stream then the internal
 * representation remains identical to the decoded data. In other words,
 * decoding and subsequent encoding of a Name object retains the order of
 * attributes and returns identical encodings.
 * <p>
 * 
 * <b>Note:</b> this class works properly only if the {@link #decode decode}
 * method is called in order to decode Names. Do not use constructions such as:
 * <blockquote><code>
 * DERDecoder dec;
 * Name rdn;
 *
 * dec = new DERDecoder(in);
 * rdn = new Name();
 * dec.readCollectionOf(rdn);
 * dec.close();
 * </code></blockquote>
 * This would work in theory but this implementation makes some assumptions in
 * order to optimise the decoding. Better use the &quot;proper&quot;
 * construction: <blockquote><code>
 * DERDecoder dec;
 * Name rdn;
 *
 * dec = new DERDecoder(in);
 * rdn = new Name();
 * rdn.decode(dec);
 * dec.close();
 * </code></blockquote>
 * This should always be safe and is the preferred way of decoding ASN.1 types
 * anyway.
 * <p>
 * 
 * Since there is only one choice at present for the Name which is RDNSequence
 * this type does not bother to implement CHOICE as its outer type. The
 * definition of Name according to X.501 as given in RSA Laboratories' Laymans
 * Guide is: <blockquote></code> Name ::= CHOICE { RDNSequence }
 * 
 * RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
 * 
 * RelativeDistinguishedName :: = SET OF AttributeValueAssertion
 * 
 * AttributeValueAssertion ::= SEQUENCE { AttributeType, AttributeValue }
 * 
 * AttributeType ::= OBJECT IDENTIFIER
 * 
 * AttributeValue ::= ANY </code></blockqoute> Since the ANY type is deprecated
 * in the '97 specification of X.680 we represent the ANY type by a generic Open
 * Type which is the new ASN.1 way of handling this.
 * <p>
 * 
 * This class supports the full range of RFC2253 features including
 * <ul>
 * <li> Quoting and escaping.
 * <li> RDNs with multiple AVAs separated by a plus sign ('+').
 * <li> OIDs as attribute keys.
 * <li> Hexadecimal attribute values introduced by a '#'. Such values must
 * constitute a valid BER encoding.
 * <li> Commas and semicolons as separators.
 * </ul>
 * 
 * The string output is canonicalized. Everything that can be resolved by this
 * class (e.g., keywords for attribute types) is resolved. The following
 * attribute types are supported per default (cf. <a
 * href="ftp://ftp.rfc-editor.org/in-notes/rfc3383.txt">RFC3383</a>:
 * <ul>
 * <li> ALIASEDOBJECTNAME (aliasedObjectName, 2.5.4.1, RFC2256)
 * <li> C (countryName, 2.5.4.6, RFC2256)
 * <li> CN (commonName, 2.5.4.3, RFC2256)
 * <li> DC (domainComponent, 0.9.2342.19200300.100.1.25, RFC2247)
 * <li> DATEOFBIRTH (dateOfBirth, 1.3.6.1.5.5.7.9.1, RFC2985)
 * <li> DNQUALIFIER (dnQualifier, 2.5.4.46, RFC2256)
 * <li> DESCRIPTION (description, 2.5.4.13, RFC2256)
 * <li> EMAILADDRESS (emailAddress, 1.2.840.113549.1.9.1, RFC2985)
 * <li> GENDER (gender, 1.3.6.1.5.5.7.9.3, RFC2985)
 * <li> GENERATION (generationQualifier, 2.5.4.44, RFC2256)
 * <li> GN (givenName, 2.5.4.42, RFC2256)
 * <li> INITIALS (initials, 2.5.4.43, RFC2256)
 * <li> IP (ip, 1.3.6.1.4.1.42.2.11.2.1, ?)
 * <li> L (localityName, 2.5.4.7, RFC2256)
 * <li> O (organizationName, 2.5.4.10, RFC2256)
 * <li> OU (organizationalUnitName, 2.5.4.11, RFC2256)
 * <li> PLACEOFBIRTH (placeOfBirth, 1.3.6.1.5.5.7.9.2, RFC2985)
 * <li> POSTALADDRESS (postalAddress, 2.5.4.16, RFC2256)
 * <li> POSTALCODE (postalCode, 2.5.4.17, RFC2256
 * <li> PSEUDONYM (pseudonym, 2.5.4.65, RFC2985)
 * <li> SERIALNUMBER (serialNumber, 2.5.4.5, RFC2256)
 * <li> SN (surName, 2.5.4.4, RFC2256)
 * <li> ST (stateOrProvinceName, 2.5.4.8, RFC2256)
 * <li> STREET (street, 2.5.4.9, RFC2256)
 * <li> UID (uid, 0.9.2342.19200300.100.1.1, RFC2253)
 * <li> TITLE (title, 2.5.4.12, RFC2256)
 * </ul>
 * 
 * @author Volker Roth
 * @author Jan Peters
 * @version "$Id: Name.java,v 1.9 2007/08/30 08:45:05 pebinger Exp $"
 */

/*
 * 
 * @author cval changed to make multiple encodings of a Name possible. behaviour
 * is like this : 1. before you use ANY name object, the static NAME_ENCODING
 * variable has to be set via a set method. the encodings are available in the
 * name class as constants. Once this variable is set, all Name objects are
 * encoded as it was set in the setNameEncoding method. For other cases, where
 * this model will not work, a special constructor is available, that gets the
 * encoding parameter by the object creator.
 */

/*
 * 
 * @author cval Following idea from MR to solve the "fixed encoding" Problem and
 * codec classes, that use implicitly the Name class. A static variable
 * "allowDefaultEncoding_" is used. If this variable is set to true, the Name
 * class works as before, using a "hardwired" default encoding. If this
 * parameter is set to false, the defaultconstructor of the Name class (Name
 * (String)) throws an Exception. This forces all classes that use the Name
 * class, to use the new constructor Name(String, Tag), where the Tag determines
 * the encoding the Name shall use (IA5, Printable ...). Before the encoding
 * takes place, the Name class checks the String, if it contains Characters,
 * that are not allowed for the chosen encoding.
 * 
 */

public class Name extends ASN1SequenceOf implements Principal, Resolver {
    /**
     * The serial version UID of the class.
     */
    private static final long serialVersionUID = 1L;

    /**
     * The &quot;match all&quot; pattern symbol.
     */
    public static final String MATCH_ALL = "*";

    /**
     * Constant for IA5Encoding of the Name
     */
    public static final int IA5_ENCODING = ASN1.TAG_IA5STRING;

    /**
     * Constant for Printable Encoding of the Name
     */
    public static final int PRINTABLE_ENCODING = ASN1.TAG_PRINTABLESTRING;

    /**
     * Constant for Teletex (T61) Encoding of the Name
     */
    public static final int T61_ENCODING = ASN1.TAG_T61STRING;

    /**
     * Constant for UTF8Encoding of the Name
     */
    public static final int UTF8_ENCODING = ASN1.TAG_UTF8STRING;

    /**
     * flag that determines, how the Name class shall behave, either as usual
     * with a default encoding or forcing all Name using classes to use the new
     * constructor.
     */
    protected static final boolean allowDefaultEncoding_ = true;

    /**
     * Determines in what kind of encoding all Name objects will be encoded as
     * long as no special constructors are used. Default is UTF8 Encoding.
     */
    protected static int defaultEncoding_ = PRINTABLE_ENCODING;

    /**
     * defines the encoding of the current Name Object
     */
    private int currentEncoding_ = defaultEncoding_;

    /**
     * The (uppercase) acronyms of the default attributes allowed in this Name
     * class.
     */
    static final String keys_[] = { "ALIASEDOBJECTNAME", "C", "CN", "DC",
	    "DATEOFBIRTH", "DNQUALIFIER", "DESCRIPTION", "EMAILADDRESS",
	    "GENDER", "GENERATION", "GN", "INITIALS", "IP", "L", "O", "OU",
	    "PLACEOFBIRTH", "POSTALADDRESS", "POSTALCODE", "PSEUDONYM",
	    "SERIALNUMBER", "SN", "ST", "STREET", "UID", "TITLE", };

    /**
     * The OID of the default attributes allowed in this Name class.
     */
    static final int oids_[][] = { { 2, 5, 4, 1 }, { 2, 5, 4, 6 },
	    { 2, 5, 4, 3 }, { 0, 9, 2342, 19200300, 100, 1, 25 },
	    { 1, 3, 6, 1, 5, 5, 7, 9, 1 }, { 2, 5, 4, 46 }, { 2, 5, 4, 13 },
	    { 1, 2, 840, 113549, 1, 9, 1 }, { 1, 3, 6, 1, 5, 5, 7, 9, 3 },
	    { 2, 5, 4, 44 }, { 2, 5, 4, 42 }, { 2, 5, 4, 43 },
	    { 1, 3, 6, 1, 4, 1, 42, 2, 11, 2, 1 }, { 2, 5, 4, 7 },
	    { 2, 5, 4, 10 }, { 2, 5, 4, 11 }, { 1, 3, 6, 1, 5, 5, 7, 9, 2 },
	    { 2, 5, 4, 16 }, { 2, 5, 4, 17 }, { 2, 5, 4, 65 }, { 2, 5, 4, 5 },
	    { 2, 5, 4, 4 }, { 2, 5, 4, 8 }, { 2, 5, 4, 9 },
	    { 0, 9, 2342, 19200300, 100, 1, 1 }, { 2, 5, 4, 12 }, };

    /**
     * Mapping from acronyms to OID.
     */
    protected HashMap a2oid_;

    /**
     * Mapping from OID to acronyms.
     */
    protected HashMap oid2a_;

    /**
     * The cached string representation.
     */
    private String name_;

    /**
     * The cached reverse string representation.
     */
    private String rname_;

    /**
     * The temporary list of AVAs that is collected during DER decoding.
     */
    List tmp_;

    /**
     * Sets the default encoding type for all further Name objects. If the
     * parameter is out of the allowed range of encodings, an Exception is
     * thrown.
     * 
     * @param encType
     * @throws BadNameException
     */
    public static void setEncodingType(int encType) throws BadNameException {
	if (encType != UTF8_ENCODING && encType != T61_ENCODING
		&& encType != PRINTABLE_ENCODING && encType != IA5_ENCODING) {
	    throw new BadNameException("Unknown EncodingType: " + encType);
	}
	defaultEncoding_ = encType;
    }

    /**
     * Returns the default encoding type.
     * 
     * @return the default encoding type.
     */
    public static int getEncodingType() {
	return defaultEncoding_;
    }

    /**
     * This constructor calls the initASN1Structure() method, do create an empty
     * structure for a Relative Distinguished Name object. Used incase one wants
     * to use the clone function for Name.
     */
    public Name() {
	super(8);
	initMaps();
    }

    /**
     * This constructor parses the given String according to <a
     * href="http://sunsite.auc.dk/RFC/">RFC2253</a> and builds the internal
     * ASN.1 representation of it in big-endian order (most significant
     * attribute first). This is the order used for encoding the name.
     * <p>
     * 
     * Any names parsed with instances of this class remain in the order they
     * were encoded in order not to invalidate any digital signatures on the
     * encoded representation when writing the encoded instance back to some
     * output stream.
     * 
     * @param rfc2253String
     *                String of RFC2253 representation.
     * @deprecated
     */
    public Name(String rfc2253String) throws BadNameException {
	this(rfc2253String, -1);
    }

    /**
     * special constructor, that overrides the global EncodingType. To use, if
     * during the runtime mixed encodingtypes are needed.
     * 
     * @param rfc2253String
     *                String of RFC2253 representation.
     * @param encType
     *                The encoding type for strings. If <code>-1</code>, the
     *                default encoding is used.
     * @throws BadNameException
     */
    public Name(String rfc2253String, int encType) throws BadNameException {
	super(8);

	ASN1ObjectIdentifier oid;
	RFC2253Parser p;
	ASN1Sequence seq;
	Iterator i;
	ASN1Set set;
	String key;
	String val;
	AVA entry;

	initMaps();

	if (encType == -1) {
	    if (!allowDefaultEncoding_) {
		throw new BadNameException(
			"Use the other constructor with the explicit "
				+ "encoding parameter!");
	    }
	    currentEncoding_ = defaultEncoding_;
	} else {
	    if (encType != UTF8_ENCODING && encType != T61_ENCODING
		    && encType != PRINTABLE_ENCODING && encType != IA5_ENCODING) {
		throw new BadNameException("Unknown EncodingType: " + encType);
	    }
	    currentEncoding_ = encType;
	}

	p = new RFC2253Parser();
	set = new ASN1Set(1);

	for (i = p.parse(rfc2253String).iterator(); i.hasNext();) {
	    entry = (AVA) i.next();
	    key = entry.getKey();
	    key = key.toUpperCase();
	    oid = (ASN1ObjectIdentifier) a2oid_.get(key);
	    seq = new ASN1Sequence(2);

	    if (oid == null) {
		try {
		    oid = new ASN1ObjectIdentifier(key);
		} catch (Exception e) {
		    throw new BadNameException("Unsupported attribute key: \""
			    + key + "\"");
		}
	    }
	    seq.add(oid.clone());

	    if (entry.isEncodedValue()) {
		ByteArrayInputStream in;
		BERDecoder dec;
		ASN1Type obj;
		byte[] buf;

		try {
		    buf = entry.getEncodedValue();
		    in = new ByteArrayInputStream(buf);
		    dec = new BERDecoder(in);
		    obj = dec.readType();

		    dec.close();
		} catch (Exception e) {
		    throw new BadNameException(
			    "Binary data is not a valid BER encoding!");
		}
		seq.add(obj);
	    } else {
		val = entry.getValue();

		/*
		 * This is a workaround for email addresses which contain the
		 * '@' symbol. This symbol is not in the character set of the
		 * ASN.1 PrintableString. Hence, we have to take a IA5String
		 * instead.
		 */
		if (entry.getKey().equalsIgnoreCase("EMAILADDRESS")
			|| entry.getKey().equalsIgnoreCase("UID")) {
		    seq.add(new ASN1IA5String(val));
		} else if (entry.getKey().equalsIgnoreCase("C")
			|| entry.getKey().equalsIgnoreCase("SERIALNUMBER")) {
		    seq.add(new ASN1PrintableString(val));
		} else {
		    switch (currentEncoding_) {
		    case (ASN1.TAG_UTF8STRING):
			seq.add(new ASN1UTF8String(val));
			break;
		    case (ASN1.TAG_IA5STRING):
			seq.add(new ASN1IA5String(val));
			break;
		    case (ASN1.TAG_PRINTABLESTRING):
			if (checkPrintableSpelling(val)) {
			    seq.add(new ASN1PrintableString(val));
			} else {
			    throw new BadNameException(
				    "Illegal characters for PrintableString "
					    + "in characters");
			}
			break;
		    case (ASN1.TAG_T61STRING):
			seq.add(new ASN1T61String(val));
			break;
		    }
		}
	    }
	    set.add(seq);

	    if (entry.hasSibling()) {
		continue;
	    }
	    set.trimToSize();

	    super.add(0, set);
	    set = new ASN1Set(1);
	}
	trimToSize();
    }

    /**
     * Clears this name instance.
     */
    public void clear() {
	super.clear();

	if (tmp_ != null) {
	    tmp_.clear();
	}
    }

    /**
     * Register user defined OID/Key-Pairs which are accepted as keys of the
     * instance's distinguished Name.
     * 
     * @param oid
     *                the OID to register as Integer array.
     * @param key
     *                the corresponding key as <code>String</code>.
     * @return <code>true</code> if neither the OID nor the key has already
     *         been registered, or is part of the default mapping. Otherwise,
     *         <code>false</code> is returned.
     */
    public boolean registerOID(int[] oid, String key) {
	ASN1ObjectIdentifier objectID;
	String keyUC;

	objectID = new ASN1ObjectIdentifier(oid);
	keyUC = key.toUpperCase();

	if (a2oid_.get(keyUC) != null || oid2a_.get(objectID) != null) {
	    return false;
	}

	a2oid_.put(keyUC, objectID);
	oid2a_.put(objectID, keyUC);
	return true;
    }

    /**
     * Returns a map containing the OID/Key-Pairs (default plus user defined),
     * which are accepted as keys of the instance's distinguished Name.
     * 
     * @return A map containing OID/Key-Entries.
     */
    public Map getOIDs() {
	return Collections.unmodifiableMap(oid2a_);
    }

    /**
     * Resets all user defined OID/Key-Pairs, which are accepted as keys of the
     * instance's distinguished Name.
     */
    public void resetOIDs() {
	initMaps();
    }

    /**
     * This method initializes the hashmaps, which are needed to create the
     * ASN1Structure Tree.
     */
    protected void initMaps() {
	int i;
	ASN1ObjectIdentifier oid;

	if (a2oid_ == null) {
	    a2oid_ = new HashMap();
	    oid2a_ = new HashMap();

	    for (i = 0; i < keys_.length; i++) {
		oid = new ASN1ObjectIdentifier(oids_[i]);

		a2oid_.put(keys_[i], oid);
		oid2a_.put(oid, keys_[i]);
	    }
	}
    }

    /**
     * Returns the encoding type that is currently set.
     * 
     * @return the encoding type that is currently set.
     */
    public int getCurrentEncoding() {
	return currentEncoding_;
    }

    /**
     * Check if the given String is printable.
     * 
     * @return <code>true</code>, iff the giben String only contains
     *         printable characters (letters, digits, or one of " (),-./:=?").
     */
    private boolean checkPrintableSpelling(String val) {
	boolean result;
	char[] allowed;
	char[] value;

	result = true;

	allowed = ("abcdefghijklmnopqrstuvwxyz" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		+ "0123456789 (),-./:=?").toCharArray();

	value = val.toCharArray();

	for (int i = 0; i < value.length; i++) {
	    for (int j = 0; j < allowed.length; j++) {
		if (value[i] == allowed[j]) {
		    break;
		}
		if (j == allowed.length - 1) {
		    return false;
		}
	    }
	}

	return result;
    }

    /**
     * Returns the String representation. This implementation simply calles
     * {@link #getName getName}.
     * 
     * @return The String representation.
     */
    public String toString() {
	return getName();
    }

    /**
     * This method returns the name of this principal. The order is
     * little-endian (least significant attribute first).
     * 
     * @return Name of this principal
     */
    public String getName() {
	StringBuffer buf;
	Iterator it;
	AVA entry;

	if (name_ != null) {
	    return name_;
	}
	buf = new StringBuffer();

	for (it = getAVAList().iterator(); it.hasNext();) {
	    entry = (AVA) it.next();

	    buf.insert(0, entry.toString());

	    // only insert a seperator, if another AVA is
	    // still in the list
	    if (it.hasNext()) {
		if (entry.hasSibling()) {
		    buf.insert(0, " + ");
		} else {
		    buf.insert(0, ", ");
		}
	    }
	}

	return buf.toString();
    }

    /**
     * This method returns the <code>Name</code> as a list of <code>AVA</code>
     * instances. The order is the same as the order in which the
     * <code>AVA</code> instances appear in the code.
     */
    public List getAVAList() {
	ASN1ObjectIdentifier oid;
	ASN1Sequence ava;
	ArrayList list;
	ASN1Type obj;
	Iterator i;
	boolean sibling;
	ASN1Set rdn;
	String val;
	String key;
	AVA entry;
	int j;
	int n;

	list = new ArrayList(size());

	for (i = iterator(); i.hasNext();) {
	    rdn = (ASN1Set) i.next();
	    n = rdn.size();

	    for (j = 0; j < n; j++) {
		/*
		 * We have to mark siblings. An AVA has a sibling if it is not
		 * the last AVA in the set.
		 */
		sibling = (j < n - 1);

		/*
		 * Convert key and value into strings. These values are then put
		 * into an AVA instance.
		 */
		ava = (ASN1Sequence) rdn.get(j);
		oid = (ASN1ObjectIdentifier) ava.get(0);
		obj = (ASN1Type) ava.get(1);
		key = (String) oid2a_.get(oid);

		if (key == null) {
		    key = oid.toString();
		}
		if (obj instanceof ASN1String) {
		    val = ((ASN1String) obj).getString();
		    entry = new AVA(key, val, sibling);
		} else {
		    /*
		     * OK, we have to encode the damn ASN.1 object. Outrageous
		     * inefficient but hey, what choice do we have, if it is not
		     * a string?
		     */
		    ByteArrayOutputStream out;
		    DEREncoder enc;

		    try {
			out = new ByteArrayOutputStream();
			enc = new DEREncoder(out);

			obj.encode(enc);

			entry = new AVA(key, out.toByteArray(), sibling);

			enc.close();
		    } catch (Exception e) {
			throw new IllegalStateException("Cannot BER encode!");
		    }
		}
		list.add(entry);
	    }
	}
	return list;
    }

    /**
     * This method returns the <code>Name</code> as a list of <code>AVA</code>
     * instances. The order is the opposite as the order in which the
     * <code>AVA</code> instances appear in the code.
     */
    public List getReverseAVAList() {
	ASN1ObjectIdentifier oid;
	ASN1Sequence ava;
	ArrayList list;
	ASN1Type obj;
	boolean sibling;
	ASN1Set rdn;
	String val;
	String key;
	AVA entry;
	int i;
	int j;
	int n;

	list = new ArrayList(size());

	for (i = size() - 1; i >= 0; i--) {
	    rdn = (ASN1Set) get(i);
	    n = rdn.size();

	    for (j = 0; j < n; j++) {
		/*
		 * We have to mark siblings. An AVA has a sibling if it is not
		 * the last AVA in the set.
		 */
		sibling = (j < n - 1);

		/*
		 * Convert key and value into strings. These values are then put
		 * into an AVA instance.
		 */
		ava = (ASN1Sequence) rdn.get(j);
		oid = (ASN1ObjectIdentifier) ava.get(0);
		obj = (ASN1Type) ava.get(1);
		key = (String) oid2a_.get(oid);

		if (key == null) {
		    key = oid.toString();
		}
		if (obj instanceof ASN1String) {
		    val = ((ASN1String) obj).getString();
		    entry = new AVA(key, val, sibling);
		} else {
		    /*
		     * OK, we have to encode the damn ASN.1 object. Outrageous
		     * inefficient but hey, what choice do we have, if it is not
		     * a string?
		     */
		    ByteArrayOutputStream out;
		    DEREncoder enc;

		    try {
			out = new ByteArrayOutputStream();
			enc = new DEREncoder(out);

			obj.encode(enc);

			entry = new AVA(key, out.toByteArray(), sibling);

			enc.close();
		    } catch (Exception e) {
			throw new IllegalStateException("Cannot BER encode!");
		    }
		}
		list.add(entry);
	    }
	}
	return list;
    }

    /**
     * This method returns the name of this principal. The order is the reverse
     * order of method {@link #getName() getName()}.
     * 
     * @return Name of this principal in reverse order of encoding.
     */
    public String getReverseName() {
	StringBuffer buf;
	Iterator i;
	AVA entry;
	int n;

	if (rname_ != null) {
	    return rname_;
	}
	buf = new StringBuffer();

	for (i = getReverseAVAList().iterator(); i.hasNext();) {
	    entry = (AVA) i.next();

	    buf.append(entry.getKey());
	    buf.append("=");

	    if (entry.isEncodedValue()) {
		buf.append("#");
		buf.append(entry.getValue());
	    } else {
		// buf.append("\"");
		buf.append(entry.getValue());
		// buf.append("\"");
	    }
	    if (entry.hasSibling()) {
		buf.append(" + ");
	    } else {
		buf.append(", ");
	    }
	}
	n = buf.length();

	/*
	 * If at least one element is in the string buffer then we have to
	 * remove a trailing comma and space.
	 */
	if (n > 0) {
	    buf.setLength(n - 2);
	}
	rname_ = buf.toString();

	return rname_;
    }

    /**
     * Resolves AttributeValueAssertions for the component RDNs of this Name.
     * This method is for internal use only. Do not call it or bad things will
     * happen. You have been warned.
     * <p>
     * 
     * This method basically registers the AVAs of the RDNs so that the internal
     * Open Types can be discarded after decoding. This makes some objects
     * available for garbage collection that are not required anymore.
     * 
     * @param caller
     *                The calling RDN.
     * @return The AVA instance that is added to the calling RDN in the decoding
     *         process.
     */
    public ASN1Type resolve(ASN1Type caller) {
	if (caller == null) {
	    throw new NullPointerException("caller");
	}
	if (tmp_ == null) {
	    tmp_ = new ArrayList(8);
	}
	ASN1Sequence seq;

	seq = new ASN1Sequence(2);

	seq.add(new ASN1ObjectIdentifier());
	seq.add(new ASN1OpenType());
	tmp_.add(seq);

	return seq;
    }

    /**
     * This method reads the DER encoded ASN.1 sequence into a hashmap. The
     * implementation uses a (perfectly legal) trick. Method
     * {@link #newElement newElement} adds the AttributeValueAssertions
     * instances to a temporary list which is processed at the end of this
     * method. The temporary list is used to eliminate Open Types that are not
     * required any more after decoding in a way that saves us laborious
     * descending in the various depths of the Name.
     * <p>
     * 
     * @param dec
     *                The {@link Decoder Decoder} to use.
     * @throws ASN1Exception
     *                 if the expected ANS1Type cannot be found.
     */
    public void decode(Decoder dec) throws ASN1Exception, IOException {
	clear();

	super.decode(dec);

	ASN1Sequence seq;
	ASN1OpenType t;
	Iterator i;
	Object o;

	for (i = tmp_.iterator(); i.hasNext();) {
	    seq = (ASN1Sequence) i.next();
	    t = (ASN1OpenType) seq.get(1);
	    o = t.getInnerType();

	    seq.set(1, o);
	}
	/*
	 * We don't need the temporary list anymore.
	 */
	tmp_ = null;
    }

    /**
     * This method adds the given object to this Name if it is a valid RDN (a
     * set with enclosed sequences with an OID and non null attribute value
     * each).
     * 
     * @param o
     *                The RDN to add.
     * @return <code>true</code>. This method accepts multiple elements which
     *         are the same, and adheres to the contract of add(Object) for
     *         collections.
     * @throws IllegalArgumentException
     *                 if the given object is not a valid RDN.
     */
    public boolean add(ASN1Set o) {
	ASN1Sequence seq;
	Iterator it;
	// Iterator j;
	ASN1Set set;
	Object p;

	if (o == null) {
	    throw new NullPointerException("parameter is null");
	}
	set = o;

	for (it = set.iterator(); it.hasNext();) {
	    p = it.next();

	    if (!(p instanceof ASN1Sequence)) {
		throw new IllegalArgumentException("not a sequence: "
			+ p.getClass().getName());
	    }
	    seq = (ASN1Sequence) p;

	    if (seq.size() != 2) {
		throw new IllegalArgumentException(
			"sequence does not have 2 elements: " + seq.size());
	    }
	    if (!(seq.get(0) instanceof ASN1ObjectIdentifier)) {
		throw new IllegalArgumentException("attribute type not an OID");
	    }
	    p = seq.get(1);

	    if (p == null || !(p instanceof ASN1Type)) {
		throw new IllegalArgumentException(
			"illegal or no attribute value");
	    }
	}
	/*
	 * Finally, we can add the RDN.
	 */
	super.add(set);

	return true;
    }

    /**
     * This method returns a new set of AttributeValueAssertions (AVA).
     * 
     * @return The new instance to decode.
     */
    public ASN1Type newElement() {
	ASN1SetOf set;

	/*
	 * Here, we add this instance as the resolver of the ASN1SetOf. Upon the
	 * 'resolve' callback, the AVAs are added to the respective RDNs.
	 */
	set = new ASN1SetOf(this, 1);
	super.add(set);

	return set;
    }

    /**
     * Compares this object with the given one. Both objects are equal if
     * <code>o</code> is a <code>Principal</code> and the name of this
     * object equals the name of <code>o</code> (or the reverse).
     * <p>
     * 
     * Both distinguished names must have the same order of RDNs and AVAs
     * withing RDNs. Strictly speaking, a RDN is a set of AVAs so the comparison
     * should tolerate that. However, this is not yet implemented.
     * <p>
     * 
     * In order to make the comparison more robust, this method converts the
     * given object into a <code>Name </code> object unless it is already of
     * that class. Then the string representation of the resulting object is
     * compared to the name of this object.
     * 
     * @param o
     *                The object to compare with.
     * @return <code>true</code> iff this instance equals the given one.
     */
    public boolean equals(Object o) {
	Hashtable table1;
	Hashtable table2;
	Enumeration en;
	Integer int1;
	Integer int2;
	String str;
	Name q;

	if (!(o instanceof Principal)) {
	    return false;
	}

	if (!(o instanceof Name)) {
	    try {
		q = new Name(((Principal) o).getName());
	    } catch (BadNameException e) {
		return false;
	    } catch (Exception e) {
		return false;
	    }
	} else {
	    q = (Name) o;
	}

	table1 = getNameTable();
	table2 = q.getNameTable();

	if (table1.size() != table2.size()) {
	    return false;
	}
	en = table1.keys();

	while (en.hasMoreElements()) {
	    str = (String) en.nextElement();

	    if (!table2.containsKey(str)) {
		return false;
	    }

	    int1 = (Integer) table1.get(str);
	    int2 = (Integer) table2.get(str);

	    if (int1.compareTo(int2) != 0) {
		return false;
	    }
	}
	return true;
    }

    /**
     * Compares the given <code>Name</code> with this <code>Name
     * </code> for
     * equality, where an asterisk ('&ast;') attribute value in this
     * <code>Name</code> matches any corresponding attribute value of the
     * given <code>Name</code>. All AVAs must appear in both
     * <code>Name</code> instances and their keys must match. If an AVA of
     * this <code>Name</code> has a sibling then the corresponding AVA of the
     * given <code>Name </code> must also have a sibling.
     * <p>
     * 
     * Please note that currently, the order of AVAs is important even though an
     * RDN is defined as a set of AVAs. Please also note that this
     * <code>Name</code> is the pattern. This is important so that attackers
     * may not get names certified that contain the &quot;match all&quot;
     * pattern as an attribute value e.g., &quot;O=&ast;&quot;.
     * 
     * @param name
     *                The <code>Name</code> to which this pattern is compared.
     */
    public boolean isPatternMatch(Name name) {
	Iterator i;
	Iterator j;
	String tmp;
	AVA ap;
	AVA an;

	if (name == null) {
	    throw new NullPointerException("name");
	}
	i = getAVAList().iterator();
	j = name.getAVAList().iterator();

	while (i.hasNext() && j.hasNext()) {
	    /*
	     * We first compare the keys for identity. This can be done case
	     * dependent because the Name implementation should be consistent
	     * with respect to the case.
	     */
	    ap = (AVA) i.next();
	    an = (AVA) j.next();
	    tmp = ap.getKey();

	    if (!tmp.equals(an.getKey())) {
		return false;
	    }
	    if (ap.hasSibling() != an.hasSibling()) {
		return false;
	    }
	    /*
	     * Next we compare the keys. Keys are matched in a case-independent
	     * way. An asterisk ("MATCH_ALL") in this name matches any value in
	     * the given name. Beware not to mix up that or attackers might try
	     * to get a way such as O=* certified.
	     */
	    tmp = ap.getValue();

	    if (tmp.equals(MATCH_ALL)) {
		continue;
	    }
	    if (!tmp.equalsIgnoreCase(an.getValue())) {
		return false;
	    }
	}
	/*
	 * Both patterns match if all AVAs match and the number of AVAs is the
	 * same.
	 */
	return (i.hasNext() == j.hasNext());
    }

    /**
     * This method checks whether this Name is contained in the given Name.
     * <code>true</code> is returned, iff all AVA defined in this Name are
     * also defined in the given Name with the same order (going from the last
     * AVA in the Name's String represenation to the first).
     * 
     * AVA siblings have the same order. AVAs are compared by attribute type and
     * value (ignoring the case of attribute type letters).
     * <p>
     * Examples: <quote>
     *              
     * <pre>
     *   name1: CN=foo + EMAILADDRESS=foo@bar.net, O=company
     *   name2: CN=foo, EMAILADDRESS=foo@bar.net, O=company
     *   name3: cn=foo, o=company
     *   name4: o=company
     *   name5: EMAILADDRESS=foo@bar.net
     *   name1.partOf(name1) == true
     *   name1.partOf(name2) == false
     *   name3.partOf(name1) == true
     *   name3.partOf(name2) == false
     *   name4.partOf(name1) == true
     *   name4.partOf(name3) == true
     *   name5.partOf(name1) == false
     *   name5.partOf(name2) == false
     * </pre></quote>
     *
     * @param name The Name to compare with.
     * @return <code>true</code> iff all known attributes of this
     *   Name are also defined in the given Name, and the
     *   corresponding values are equal (ignoring case).
     */
    public boolean partOf(Name name) {
	Hashtable table1;
	Hashtable table2;
	Enumeration e;
	Integer ord1;
	Integer ord2;
	String str;

	if (name == null) {
	    return false;
	}

	table1 = getNameTable();
	table2 = name.getNameTable();
	e = table1.keys();

	while (e.hasMoreElements()) {
	    str = (String) e.nextElement();

	    if (!table2.containsKey(str)) {
		return false;
	    }
	    ord1 = (Integer) table1.get(str);
	    ord2 = (Integer) table2.get(str);

	    if (ord1.compareTo(ord2) != 0) {
		return false;
	    }
	}
	return true;
    }

    /**
     * Clone the given Name.
     * 
     * @param source
     * @return the cloned Name
     * @deprecated
     */
    public static Name clone(Name source) throws IllegalArgumentException {
	ASN1Sequence seq;
	Vector sets;
	Name result;

	result = null;

	if (source == null || source.getName().length() == 0) {
	    throw new IllegalArgumentException(
		    "Name/Principal must not be null nor empty !");
	}
	seq = source;
	sets = new Vector();

	for (int i = 0; i < seq.size(); i++) {
	    sets.add(seq.get(i));
	}
	result = new Name();

	for (int j = 0; j < sets.size(); j++) {
	    result.add((ASN1Set) sets.elementAt(j));
	}
	return result;
    }

    /**
     * Clone the Name from given Principal.
     * 
     * @param sourcePrincipal
     * @return the cloned Name
     * @throws BadNameException
     * @deprecated
     */
    public static Name clone(Principal sourcePrincipal)
	    throws BadNameException, IllegalArgumentException {

	if (sourcePrincipal == null || sourcePrincipal.getName().length() == 0) {
	    throw new IllegalArgumentException(
		    "Name/Principal must not be null nor empty !");
	}

	/*
	 * WARNING : Since there is no Encoding Information, the Name will be
	 * encoded in the Name class default encoding.
	 */
	return new Name(sourcePrincipal.getName(), Name.defaultEncoding_);
    }

    /**
     * Added by Jens Zoerkler function divides the Name into his RDN parts and
     * puts them into a Hashtable, where the key is the RDNs identifier and
     * value is the value of the RDN.
     * 
     * @return Hashtable
     */
    public Hashtable divide() {
	StringTokenizer st;
	Hashtable result;
	List list;
	int iou;
	int j;
	int i;

	result = new Hashtable();
	list = getAVAList();
	iou = 0;

	for (i = 0; i < list.size(); i++) {
	    AVA ava = (AVA) list.get(i);

	    if ("1.2.840.113549.1.9.2".equals(ava.getKey())) { // UN
		result.put("UN", ava.getValue());

		st = new StringTokenizer(ava.getValue(), ".");
		j = 0;

		while (st.hasMoreTokens()) {
		    j++;
		    result.put("UN" + j, st.nextToken());
		}
	    } else if ("1.2.840.113549.1.9.8".equals(ava.getKey())) { // UA
		// unstructured
		// adress
		result.put("UA", ava.getValue());
	    } else if ("OU".equals(ava.getKey())) {
		if (result.get("OU") == null) {
		    result.put("OU", ava.getValue());
		} else { // there was already a OU
		    result.put("OU0", result.get("OU"));
		    iou++;
		    result.put("OU" + iou, ava.getValue());
		}
	    } else {
		result.put(ava.getKey(), ava.getValue());
	    }
	}
	return result;
    }

    /**
     * This function returns a Hashtable object with the following properties:
     * 
     * <ul>
     * <li>The keys are the attribute type/value entries defined in this Name
     * object. If the same type/value entry is used more than once in the Name
     * object, its key is extended with a trailing number to distinguish the
     * single AVAs.
     * <li>Each value is a vector of two elements; the first element is the
     * corresponding attribute type and the second element is the order in which
     * they are read from the parser with respect to ",", which means that if
     * two pairs: (attribute type = attribute value) are separated by "," their
     * order will be different and if two pairs are separarted by "+" then they
     * will have the same order.
     * </ul>
     * 
     * Examples:
     * 
     * <quote>
     *              
     * <pre>
     *   (new Name(&quot;DC=www, DC=www + DC=WWW&quot;)).getNameTable(true)
     *   -&gt; [ (DC=WWW|1), (DC=www|1), (DC1=www|2) ]
     * </pre></quote>
     *
     * @return the Hashtable.
     */
    protected Hashtable getNameTable() {
	Hashtable nameTable;
	Iterator it;
	String key;
	int order;
	AVA entry;
	int i;

	order = 1;
	nameTable = new Hashtable();
	it = getAVAList().iterator();

	while (it.hasNext()) {
	    entry = (AVA) it.next();
	    key = entry.toString();
	    i = 1;

	    while (nameTable.containsKey(key)) {
		key = (new AVA(entry.getKey() + i, entry.getValue(), entry
			.hasSibling())).toString();

		i++;
	    }
	    nameTable.put(key, new Integer(order));

	    if (!entry.hasSibling()) {
		order = order + 1;
	    }
	}
	return nameTable;
    }
}
