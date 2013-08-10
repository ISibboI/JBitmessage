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
package codec.x509.extensions;

import java.io.IOException;
import java.util.Iterator;

import codec.asn1.ASN1BitString;
import codec.asn1.ASN1Boolean;
import codec.asn1.ASN1Exception;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1SequenceOf;
import codec.asn1.ASN1TaggedType;
import codec.asn1.Decoder;
import codec.x509.GeneralName;
import codec.x509.X509Extension;

/**
 * <pre>
 * IssuingDistPointSyntax ::= SEQUENCE {
 * distributionPoint	[0] DistributionPointName OPTIONAL,
 * onlyContainsUserCerts	[1] BOOLEAN DEFAULT FALSE,
 * onlyContainsCACerts	[2] BOOLEAN DEFAULT FALSE,
 * onlySomeReasons		[3] ReasonFlags OPTIONAL,
 * indirectCRL		[4] BOOLEAN DEFAUTL FALSE
 * }
 *  ReasonFlags ::= BIT STRING {
 *       unused                  (0),
 *       keyCompromise           (1),
 *       cACompromise            (2),
 *       affiliationChanged      (3),
 *       superseded              (4),
 *       cessationOfOperation    (5),
 *       certificateHold         (6)
 *  }
 * </pre>
 * 
 * @author cval
 */
public class IssuingDistPoint extends X509Extension {
    public static final int TAG_DISTRIBUTION_POINT = 0;
    public static final int TAG_CONTAINS_USER_CERTS = 1;
    public static final int TAG_CONTAINS_CA_CERTS = 2;
    public static final int TAG_SOME_REASONS = 3;
    public static final int TAG_INDIRECT_CRL = 4;
    public static final int TAG_FULL_NAME = 0;

    public static final String ID_CE_ISSUING_DISTRIBUTION_POINT = "2.5.29.28";

    private ASN1TaggedType distributionPointTag_;
    private ASN1TaggedType distributionPoint_;

    /*
     * The only CHOICE we support. This is linked into distributionPoint by
     * means of an ASN1TaggedType.
     */
    private ASN1Sequence fullName_;

    private ASN1TaggedType containsUserCertsTag_;
    private ASN1Boolean containsUserCerts_;

    private ASN1TaggedType containsCaCertsTag_;
    private ASN1Boolean containsCaCerts_;

    private ASN1TaggedType someReasonsTag_;
    private ASN1BitString someReasons_;

    private ASN1TaggedType indirectCrlTag_;
    private ASN1Boolean indirectCrl_;

    private ASN1Sequence idp;

    public IssuingDistPoint() throws Exception {
	idp = new ASN1Sequence(5);

	setOID(new ASN1ObjectIdentifier(ID_CE_ISSUING_DISTRIBUTION_POINT));
	setCritical(true);
	/*
	 * We do not support both choices of DistributionPointName, hence we
	 * directly initialize the one we support rather than going through an
	 * ASN1Choice (which just adds another layer of complication).
	 */

	fullName_ = new ASN1SequenceOf(GeneralName.class);

	/*
	 * We wrap the only CHOICE we support into the appropriate tagged type.
	 */
	distributionPoint_ = new ASN1TaggedType(TAG_FULL_NAME, fullName_,
		false, false);

	/*
	 * We wrap again. Flags are EXPLICIT and OPTIONAL.
	 */
	distributionPointTag_ = new ASN1TaggedType(TAG_DISTRIBUTION_POINT,
		distributionPoint_, true, true);
	/*
	 * Finally, we add the tagged type.
	 */
	idp.add(distributionPointTag_);

	/*
	 * Next element with tag [1].
	 */
	containsUserCerts_ = new ASN1Boolean(false);
	containsUserCertsTag_ = new ASN1TaggedType(TAG_CONTAINS_USER_CERTS,
		containsUserCerts_, false, true);
	idp.add(containsUserCertsTag_);

	/*
	 * next element with tag [2].
	 */
	containsCaCerts_ = new ASN1Boolean(false);
	containsCaCertsTag_ = new ASN1TaggedType(TAG_CONTAINS_CA_CERTS,
		containsCaCerts_, false, true);
	idp.add(containsCaCertsTag_);

	/*
	 * next element with tag [3].
	 */
	someReasons_ = new ASN1BitString();
	someReasonsTag_ = new ASN1TaggedType(TAG_SOME_REASONS, someReasons_,
		false, true);
	idp.add(someReasonsTag_);

	/*
	 * Final element with tag [4].
	 */
	indirectCrl_ = new ASN1Boolean(false);
	indirectCrlTag_ = new ASN1TaggedType(TAG_INDIRECT_CRL, indirectCrl_,
		false, true);
	idp.add(indirectCrlTag_);
	setValue(idp);
    }

    public void setContainsUserCerts(boolean userCerts) throws Exception {

	containsUserCerts_.setTrue(userCerts);
	containsUserCertsTag_.setOptional(false);
	setValue(idp);
    }

    public void setContainsCaCerts(boolean caCerts) throws Exception {
	containsCaCerts_.setTrue(caCerts);
	containsCaCertsTag_.setOptional(false);
	setValue(idp);
    }

    public void addDistributionPointName(GeneralName aName) throws Exception {
	fullName_.add(aName);
	distributionPointTag_.setOptional(false);
	setValue(idp);
    }

    public void setSomeReasons(boolean flags[]) throws Exception {
	if (flags.length > 7) {
	    throw new ASN1Exception("Wrong number of flags!");
	}
	someReasons_.setBits(flags);
	someReasonsTag_.setOptional(false);
	setValue(idp);
    }

    public void addIndirectCrl(boolean indirect) throws Exception {
	indirectCrl_.setTrue(indirect);
	indirectCrlTag_.setOptional(false);
	setValue(idp);
    }

    public void decode(Decoder dec) throws ASN1Exception, IOException {
	super.decode(dec);
	super.decodeExtensionValue(idp);
    }

    /**
     * returns the ASN1SequenceOf that contains the GeneralNames with the
     * distribution point URL's. Note that RelativeDistinguishedNames are NOT
     * supported yet and will return null in this case!
     */
    public ASN1Sequence getDistributionPointNames() {
	if (distributionPointTag_.isOptional()) {
	    return null;
	}
	return fullName_;
    }

    /**
     * returns the boolean value of containsUserCerts.
     */
    public boolean onlyContainsUserCerts() {
	return this.containsUserCerts_.isTrue();
    }

    /**
     * returns the boolean value of containsCaCerts.
     */
    public boolean onlyCaCerts() {
	return this.containsCaCerts_.isTrue();
    }

    /**
     * returns the boolean value of indirectCrl.
     */
    public boolean indirectCrl() {
	return this.indirectCrl_.isTrue();
    }

    /**
     * returns the boolean array of someReasons
     */
    public ASN1BitString someReasons() {
	return this.someReasons_;
    }

    /**
     * returns an array of Strings containing all CRL-DP URL's
     * RelativeDistinguishedName not implemented yet!
     */
    public String[] getDPURLs() {
	ASN1Sequence names;
	GeneralName gn;
	Iterator i;
	String[] res;
	int n;

	names = getDistributionPointNames();

	if (names == null) {
	    return null;
	}
	res = new String[names.size()];

	for (n = 0, i = names.iterator(); i.hasNext(); n++) {
	    try {
		gn = (GeneralName) i.next();
		res[n] = gn.getGeneralName().getValue().toString();
	    } catch (codec.x509.X509Exception ex) {
		res[n] = "<could not decode this URL!>";
	    }
	}
	return res;
    }

    public String toString(String offset) {
	StringBuffer buf;
	String[] dps;

	buf = new StringBuffer(offset + "IssuingDistributionPoint {\n");
	dps = getDPURLs();

	if (dps == null) {
	    buf.append(offset + "No URLs\n");
	} else {
	    for (int i = 0; i < dps.length; i++) {
		buf.append(offset + dps[i]);
		buf.append("\n");
	    }
	}
	buf.append("CRL Issuers:\n" + containsCaCerts_);

	buf.append(offset + "}\n");

	return buf.toString();
    }

    public String toString() {
	return toString("");
    }
}
