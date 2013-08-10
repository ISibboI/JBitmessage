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
import java.security.cert.CertificateEncodingException;

import codec.asn1.ASN1Exception;
import codec.asn1.ASN1GeneralizedTime;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1UTCTime;
import codec.asn1.Decoder;
import codec.x509.X509Extension;

/**
 * 
 * @author Volker Roth
 * @version "$Id: ArchiveCutoffExtension.java,v 1.1 2004/08/16 13:31:38 pebinger
 *          Exp $"
 */
public class ArchiveCutoffExtension extends X509Extension {
    public static final String EXTENSION_OID = "1.3.6.1.5.5.7.48.1.6";

    private ASN1GeneralizedTime time_;

    public ArchiveCutoffExtension() throws ASN1Exception,
	    CertificateEncodingException {
	this(new ASN1GeneralizedTime(System.currentTimeMillis()));
    }

    public ArchiveCutoffExtension(ASN1GeneralizedTime time)
	    throws ASN1Exception, CertificateEncodingException {
	if (time == null) {
	    throw new NullPointerException("time");
	}
	time_ = time;

	/*
	 * Big question: is this extension critical or not? ISIS-MTT given the
	 * code '--' in the table. This *probably* means not critical...
	 */
	setCritical(false);
	setOID(new ASN1ObjectIdentifier(EXTENSION_OID));
	setValue(time_);
    }

    public ArchiveCutoffExtension(ASN1UTCTime time) throws ASN1Exception,
	    CertificateEncodingException {
	if (time == null) {
	    throw new NullPointerException("time");
	}

	/*
	 * Big question: is this extension critical or not? ISIS-MTT given the
	 * code '--' in the table. This *probably* means not critical...
	 */
	setCritical(false);
	setOID(new ASN1ObjectIdentifier(EXTENSION_OID));
	setValue(time_);
    }

    /**
     * @return The internal ASN.1 object which represents the time.
     */
    public ASN1GeneralizedTime getTime() {
	return time_;
    }

    public void decode(Decoder dec) throws ASN1Exception, IOException {
	super.decode(dec);
	super.decodeExtensionValue(time_);
    }

}
