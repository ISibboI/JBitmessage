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

import codec.asn1.ASN1Enumerated;
import codec.asn1.ASN1Exception;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1Type;
import codec.asn1.Decoder;
import codec.x509.X509Exception;
import codec.x509.X509Extension;

/**
 * @author mal
 * 
 * <pre>
 *  
 * id-ce-cRLReason OBJECT IDENTIFIER ::= { id-ce 21 }
 * 
 * reasonCode = { CRLReason }
 * 
 * CRLReason ::= ENUMERATED {
 *    unspecified             (0),
 *    keyCompromise           (1),
 *    cACompromise            (2),
 *    affiliationChanged      (3),
 *    superseded              (4),
 *    cessationOfOperation    (5),
 *    certificateHold         (6),
 *    removeFromCRL           (8) }
 *  id-ce OBJECT IDENTIFIER  ::=  {joint-iso-ccitt(2) ds(5) 29}
 * }
 * </pre>
 * 
 */
public class ReasonCodeExtension extends X509Extension {

    /**
     * This is the object identifier (OID) of this extension
     */
    protected static final String ID_CE_CRL_REASON = new String("2.5.29.21");

    protected ASN1Enumerated theReason;

    /**
     * These are the possible reason codes
     */
    public static final int REASON_UNSPECIFIED = 0;
    public static final int REASON_KEY_COMPROMISE = 1;
    public static final int REASON_CA_COMPROMISE = 2;
    public static final int REASON_AFFILIATION_CHANGE = 3;
    public static final int REASON_SUPERSEDED = 4;
    public static final int REASON_CESSATION_OF_OPERATION = 5;
    public static final int REASON_CERTIFICATE_HOLD = 6;
    public static final int REASON_REMOVE_FROM_CRL = 8;

    /**
     * Constructor for ReasonCodeExtension.
     * 
     * @throws Exception
     */
    public ReasonCodeExtension() throws Exception {
	this(REASON_UNSPECIFIED);
    }

    public ReasonCodeExtension(int aReason) throws Exception {
	super.setOID(new ASN1ObjectIdentifier(ID_CE_CRL_REASON));
	setReasonCode(aReason);
    }

    /**
     * This constructor basically calls the related constructor in the base
     * class.
     * 
     * @param ext
     * @throws ASN1Exception
     * @throws IOException
     */
    public ReasonCodeExtension(byte[] ext) throws ASN1Exception, IOException {
	super(ext);
    }

    public void setReasonCode(int aReason) throws Exception {
	/*
	 * Why not check for > 7 in the first place? Even better would be the
	 * declaration of a constant upper bound CODE_MAX which is declared
	 * where the reason codes are declared. This avoids nasty bugs should
	 * the reason codes be extended (without fixing the code in all relevant
	 * places as well, which is easily forgotten).
	 * 
	 * --volker roth
	 */
	if ((aReason < 0) || (aReason == 7) || (aReason > 8)) {
	    throw new X509Exception("Reasoncode unknown");
	}
	theReason = new ASN1Enumerated(aReason);
	super.setValue(theReason);
    }

    public void decode(Decoder dec) throws ASN1Exception, IOException {
	super.decode(dec);

	ASN1Type inner = (ASN1Type) super.getValue();

	if (!(inner instanceof ASN1Enumerated)) {
	    throw new ASN1Exception("unexpected extension value "
		    + inner.toString());
	}
	theReason = (ASN1Enumerated) inner;
    }

    public String toString() {
	return toString("");
    }

    public String toString(String offset) {
	StringBuffer buf = new StringBuffer(offset + "ReasonCodeExtension ["
		+ ID_CE_CRL_REASON + "] {");

	if (isCritical()) {
	    buf.append(" (CRITICAL)\n");
	} else {
	    buf.append(" (NOT CRITICAL)\n");
	}

	buf.append(offset + "reason: ");
	switch (((ASN1Enumerated) getValue()).getBigInteger().intValue()) {
	case REASON_UNSPECIFIED:
	    buf.append("unspecified");
	    break;
	case REASON_KEY_COMPROMISE:
	    buf.append("key compromise");
	    break;
	case REASON_AFFILIATION_CHANGE:
	    buf.append("affiliation change");
	    break;
	case REASON_SUPERSEDED:
	    buf.append("superseded");
	    break;
	case REASON_CESSATION_OF_OPERATION:
	    buf.append("cessation of operation");
	    break;
	case REASON_CERTIFICATE_HOLD:
	    buf.append("certificate hold");
	    break;
	case REASON_REMOVE_FROM_CRL:
	    buf.append("remove from crl");
	    break;
	default:
	    buf.append("unknown reason code");
	    break;
	}
	buf.append("\n" + offset + "}\n");
	return buf.toString();
    }

}
