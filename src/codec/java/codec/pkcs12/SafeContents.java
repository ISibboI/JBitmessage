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

import codec.asn1.ASN1BMPString;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1OctetString;
import codec.asn1.ASN1RegisteredType;
import codec.asn1.ASN1SequenceOf;
import codec.x501.Attribute;

/**
 * This class represents a <code>SafeContents</code> as defined in <a
 * href="http://www.rsasecurity.com/rsalabs/pkcs/pkcs-12/index.html"> PKCS#12</a>.
 * The ASN.1 definition of this structure is
 * <p>
 * 
 * <pre>
 * SafeContents  ::= SEQUENCE OF SafeBag
 * SafeBags can be of type {@link KeyBag keyBag},
 * {@link PKCS8ShroudedKeyBag pkcs8ShroudedKeyBag}, {@link CertBag certBag},
 * {@link CRLBag crlBag}, {@link SecretBag secretBag},
 * {@link SafeContents safeContents}.  All of these types have
 * registered OIDs.
 * &#064;author Michele Boivin
 * &#064;version &quot;$Id: SafeContents.java,v 1.4 2005/03/22 14:13:20 flautens Exp $&quot;
 * 
 */
public class SafeContents extends ASN1SequenceOf implements
	java.io.Serializable {
    /**
     * The OID of this structure.
     */
    protected static final int[] OID_ = { 1, 2, 840, 113549, 1, 12, 10, 1, 6 };

    /**
     * The OID for the Attribute friendlyName
     */
    protected static final int[] FN_OID_ = { 1, 2, 840, 113549, 1, 9, 20 };

    /**
     * The OID for the Attribute localKeyId
     */
    protected static final int[] LK_OID_ = { 1, 2, 840, 113549, 1, 9, 21 };

    /**
     * the default constructor.
     */
    public SafeContents() {
	super(SafeBag.class);
    }

    /**
     * Constructs a SafeContents from a SafeBag.
     * 
     * @param bag
     *                The SafeBag to put in the SafeContents
     */
    public SafeContents(ASN1RegisteredType bag) {
	super(SafeBag.class);
	addSafeBag(bag);
    }

    /**
     * Constructs a SafeContents from a SafeBag.
     * 
     * @param bag
     *                The SafeBag to put in the SafeContents.
     * @param attr
     *                an array of bag attributes.
     */
    public SafeContents(ASN1RegisteredType bag, Attribute[] attr) {
	super(SafeBag.class);
	addSafeBag(bag, attr);
    }

    /**
     * Constructs a SafeContents from a SafeBag and sets the attributes
     * friendlyName and localKeyId.
     * 
     * @param bag
     *                The SafeBag to put in the SafeContents
     * @param user_fn
     *                The friendlyName
     * @param lk_id
     *                The localKeyId
     */
    public SafeContents(ASN1RegisteredType bag, String user_fn, byte[] lk_id) {
	super(SafeBag.class);
	Attribute attrUserFn = null;
	Attribute attrUserKeyId = null;

	// Add friendlyName (if present)
	if ((user_fn != null) && !user_fn.equals("")) {
	    ASN1ObjectIdentifier fnOID = new ASN1ObjectIdentifier(FN_OID_);
	    attrUserFn = new Attribute(fnOID, new ASN1BMPString(user_fn));
	}

	// add localKeyId (if present)
	if ((lk_id != null) && (lk_id.length > 0)) {
	    ASN1ObjectIdentifier lkOID = new ASN1ObjectIdentifier(LK_OID_);
	    attrUserKeyId = new Attribute(lkOID, new ASN1OctetString(lk_id));
	}

	// both present -> add both
	if ((user_fn != null) && (lk_id != null)) {
	    Attribute[] attr = new Attribute[2];
	    attr[0] = attrUserFn;
	    attr[1] = attrUserKeyId;
	    addSafeBag(bag, attr);
	} else {
	    // only one of them present?
	    if ((user_fn == null) && (lk_id != null)) {
		Attribute[] attr = new Attribute[1];
		attr[0] = attrUserKeyId;
		addSafeBag(bag, attr);
	    } else { // the other one?
		if ((user_fn != null) && (lk_id == null)) {
		    Attribute[] attr = new Attribute[1];
		    attr[0] = attrUserFn;
		    addSafeBag(bag, attr);
		} else {
		    addSafeBag(bag);
		}
	    }
	}
    }

    /**
     * Adds a SafeBag to the SafeContents.
     * 
     * @param bag
     *                the bag to be added to the SafeContents.
     */
    public void addSafeBag(ASN1RegisteredType bag) {
	SafeBag safeBag = new SafeBag();
	safeBag.setBagContents(bag);
	add(safeBag);
    }

    /**
     * Adds a SafeBag to the SafeContents.
     * 
     * @param bag
     *                the bag to be added to the SafeContents.
     * @param attr
     *                an array of bag attributes.
     */
    public void addSafeBag(ASN1RegisteredType bag, Attribute[] attr) {
	SafeBag safeBag = new SafeBag();
	safeBag.setBagContents(bag);
	safeBag.setAttributes(attr);
	add(safeBag);
    }

    /**
     * A SafeContents can be put recursively into a SafeBag.
     * 
     * @return the OID defining this structure as a SafeContents bag.
     */
    public ASN1ObjectIdentifier getOID() {
	return new ASN1ObjectIdentifier(OID_);
    }

    /**
     * returns the SafaBag at position i.
     * 
     * @param i
     *                The integer specifying the position.
     * @return The SafeBag at position i.
     */
    public SafeBag getSafeBag(int i) {
	return (SafeBag) (this.get(i));
    }

    /**
     * returns the contents of the SafeContents as an array.
     * 
     * @return an array of SafeBags.
     */
    public SafeBag[] getSafeBags() {
	SafeBag[] safeArray = new SafeBag[this.size()];
	for (int i = 0; i < this.size(); i++) {
	    safeArray[i] = (SafeBag) (this.get(i));
	}
	return safeArray;
    }
}
