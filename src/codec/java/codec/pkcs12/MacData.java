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

import codec.asn1.ASN1Integer;
import codec.asn1.ASN1OctetString;
import codec.asn1.ASN1Sequence;
import codec.pkcs1.DigestInfo;

/**
 * This class represents a <code>MacData</code> as defined in <a
 * href="http://www.rsasecurity.com/rsalabs/pkcs/pkcs-12/index.html"> PKCS#12</a>.
 * The ASN.1 definition of this structure is
 * <p>
 * 
 * <pre>
 *  MacData::= SEQUENCE {
 *   mac         DigestInfo,
 *   macSalt     OCTET STRING,
 *   iterations  INTEGER DEFAULT 1
 *   }
 * </pre>
 * 
 * <p>
 * <code>PFX</code>
 * 
 * 
 * @author Michele Boivin, Markus Tak
 * @version "$Id: MacData.java,v 1.3 2003/01/28 04:46:06 jpeters Exp $"
 */
public class MacData extends ASN1Sequence implements java.io.Serializable {

    /**
     * The mac data
     */
    protected DigestInfo mac_;

    /**
     * the salt used to produce the mac key
     */
    protected ASN1OctetString macSalt_;

    /**
     * the number of iterations
     */
    protected ASN1Integer iter_ = new ASN1Integer(1);

    /**
     * Default constructor. Builds up the ASN.1 structure
     */
    public MacData() {
	super(3);

	mac_ = new DigestInfo();
	add(mac_);

	macSalt_ = new ASN1OctetString();
	add(macSalt_);

	iter_ = new ASN1Integer();
	iter_.setOptional(true);
	add(iter_);
    }

    /**
     * Constructor upon input data
     */
    public MacData(DigestInfo digest, byte[] salt, int it) {
	super(3);

	mac_ = digest;
	add(mac_);

	macSalt_ = new ASN1OctetString(salt);
	add(macSalt_);

	iter_ = new ASN1Integer(it);
	if (it == 1) // default value?
	    iter_.setOptional(true);
	add(iter_);
    }

    public int getIterationCount() {
	if (iter_.isOptional() == true)
	    return 1;
	return iter_.getBigInteger().intValue();
    }

    public DigestInfo getMacData() {
	return mac_;
    }

    public byte[] getSalt() {
	return macSalt_.getByteArray();
    }
}
