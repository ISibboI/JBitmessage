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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;

import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1RegisteredType;
import codec.asn1.ASN1Type;
import codec.pkcs8.PrivateKeyInfo;
import codec.x509.AlgorithmIdentifier;

/**
 * This class represents a <code>KeyBag</code> as defined in <a
 * href=""http://www.rsasecurity.com/rsalabs/pkcs/pkcs-12/index.html> PKCS#12</a>.
 * The ASN.1 definition of this structure is
 * <p>
 * 
 * <pre>
 * KeyBag::= PrivateKeyInfo
 * </pre>
 * 
 * <p>
 * <code>PrivateKeyInfo</code> is defined in PKCS#8, the Private Key
 * Information Syntax Standard.
 * <p>
 * 
 * @author Michele Boivin
 * @version "$Id: KeyBag.java,v 1.4 2005/03/22 14:05:26 flautens Exp $"
 */
public class KeyBag extends PrivateKeyInfo implements ASN1RegisteredType,
	java.io.Serializable {
    /**
     * The OID of this structure. PrivateKeyInfo.
     */
    private static final int[] OID_ = { 1, 2, 840, 113549, 1, 12, 10, 1, 1 };

    /**
     * default constructor.
     */
    public KeyBag() {
	super();
    }

    /**
     * 
     */
    public KeyBag(AlgorithmIdentifier aID, byte[] key) {
	super(aID, key);
    }

    /**
     * 
     */
    public KeyBag(AlgorithmIdentifier aID, ASN1Type key) {
	super(aID, key);
    }

    /**
     * 
     */
    public KeyBag(java.security.PrivateKey pk) throws InvalidKeyException {
	super(pk);
    }

    /**
     * Returns the ObjectIdentifier for this bagtype.
     * 
     * @return the ObjectIdentifier
     */
    public ASN1ObjectIdentifier getOID() {
	return new ASN1ObjectIdentifier(OID_);
    }

    /**
     * Returns the private key
     * 
     * @return The private key
     * @throws NoSuchAlgorithmException
     *                 DOCUMENT ME!
     */
    public PrivateKey getPrivateKey() throws NoSuchAlgorithmException {
	return super.getPrivateKey();
    }

    /**
     * @return the string that describes this Keybag object.
     */
    public String toString() {
	return super.toString() + "\n}";
    }
}
