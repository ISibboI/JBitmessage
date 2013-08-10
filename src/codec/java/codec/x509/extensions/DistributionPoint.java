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

import java.util.Iterator;

import codec.asn1.ASN1BitString;
import codec.asn1.ASN1Exception;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1SequenceOf;
import codec.asn1.ASN1TaggedType;
import codec.x509.GeneralName;

/**
 * <pre>
 *  DistributionPoint ::= SEQUENCE {
 *       distributionPoint       [0] EXPLICIT DistributionPointName OPTIONAL,
 *       reasons                 [1] IMPLICIT ReasonFlags OPTIONAL,
 *       cRLIssuer               [2] IMPLICIT GeneralNames OPTIONAL
 *  }
 *  DistributionPointName ::= CHOICE {
 *       fullName                [0] IMPLICIT GeneralNames,
 *       nameRelativeToCRLIssuer [1] IMPLICIT RelativeDistinguishedName
 *  } NOT IMPLEMENTED YET
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
 */
public class DistributionPoint extends ASN1Sequence {
    public static final int TAG_DISTRIBUTION_POINT = 0;
    public static final int TAG_REASONS = 1;
    public static final int TAG_CRL_ISSUER = 2;
    public static final int TAG_FULL_NAME = 0;

    private ASN1TaggedType distributionPointTag_;
    private ASN1TaggedType distributionPoint_;

    /*
     * The only CHOICE we support. This is linked into distributionPoint by
     * means of an ASN1TaggedType.
     */
    private ASN1Sequence fullName_;

    private ASN1TaggedType reasonsTag_;
    private ASN1BitString reasons_;

    private ASN1TaggedType cRLIssuerTag_;
    private ASN1Sequence cRLIssuer_;

    public DistributionPoint() {
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
	add(distributionPointTag_);

	/*
	 * Next element with tag [1].
	 */
	reasons_ = new ASN1BitString();
	reasonsTag_ = new ASN1TaggedType(TAG_REASONS, reasons_, false, true);
	add(reasonsTag_);

	/*
	 * Final element with tag [2].
	 */
	cRLIssuer_ = new ASN1SequenceOf(GeneralName.class);
	cRLIssuerTag_ = new ASN1TaggedType(TAG_CRL_ISSUER, cRLIssuer_, false,
		true);
	add(cRLIssuerTag_);
    }

    public void setReasons(boolean flags[]) throws ASN1Exception {
	if (flags.length > 7) {
	    throw new ASN1Exception("Wrong number of flags!");
	}
	reasons_.setBits(flags);
	reasonsTag_.setOptional(false);
    }

    public void addDistributionPointName(GeneralName aName) {
	fullName_.add(aName);
	distributionPointTag_.setOptional(false);
    }

    public void addCRLIssuer(GeneralName aName) {
	cRLIssuer_.add(aName);
	cRLIssuerTag_.setOptional(false);
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

	buf = new StringBuffer(offset + "DistributionPoint {\n");
	dps = getDPURLs();

	if (dps == null) {
	    buf.append(offset + "No URLs\n");
	} else {
	    for (int i = 0; i < dps.length; i++) {
		buf.append(offset + dps[i]);
		buf.append("\n");
	    }
	}
	if (!this.cRLIssuerTag_.isOptional()) {
	    buf.append("CRL Issuers:\n" + cRLIssuer_.toString());
	}

	buf.append(offset + "}\n");

	return buf.toString();
    }

    public String toString() {
	return toString("");
    }
}
