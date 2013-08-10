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

import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1OctetString;
import codec.asn1.ASN1PrintableString;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1SequenceOf;
import codec.asn1.ASN1TaggedType;
import codec.asn1.ASN1UTF8String;

/**
 * Class implements the ASN1Structure ProfessionInfo as a pert of the Admission
 * Extension.
 * 
 * ProfessionInfo ::= SEQUENCE {
 * 
 * namingAuthority [0] EXPLICIT NamingAuthority Optional, professionItems
 * Sequence Of DirectoryString, professionOIDs Sequence Of ObjectIdentifiers
 * Optional, registrationNumber PrintableString(SIZE(1...128)) Optional,
 * addProfessionInfo OctetString Optional }
 * 
 * @author cval
 * 
 */

public class ProfessionInfo extends ASN1Sequence {

    /**
     * Sequence holding the ProfessionItems, at least one, up to many.
     */
    private ASN1Sequence professionItems = null;

    /**
     * Sequence holding the Profession OIDs, at least one, up to many.
     */
    private ASN1Sequence professionOids = null;

    /**
     * NamingAuthority Tag
     */
    private static final int TAG_NAMING_AUTH = 0;

    /**
     * NamingAuthority Tagged Type
     */
    private ASN1TaggedType namingAuthTag;

    /**
     * NamingAuthority Structure
     */
    private NamingAuthority namingAuth = null;

    /**
     * Registrationnumber
     */
    private ASN1PrintableString registrationNumber = null;

    /**
     * additional Professioninfo, coded in an octect String.
     */
    private ASN1OctetString addProfessionInfo = null;

    public ProfessionInfo() {
	professionItems = new ASN1SequenceOf(ASN1UTF8String.class);
	professionOids = new ASN1SequenceOf(ASN1ObjectIdentifier.class);
    }

    public void addNamingAuthority(NamingAuthority na) {
	namingAuth = na;
	namingAuthTag = new ASN1TaggedType(TAG_NAMING_AUTH, namingAuth, true,
		false);
	add(namingAuthTag);
    }

    public void addProfessionItem(ASN1Sequence item) {
	professionItems = item;
	add(professionItems);
    }

    public void addProfessionOid(ASN1SequenceOf oid) {
	professionOids = oid;
	add(professionOids);
    }

    public void addRegistrationNumber(ASN1PrintableString reg) {
	registrationNumber = reg;
	add(registrationNumber);
    }

    public void addAddProfessionInfo(ASN1OctetString addInfo) {
	addProfessionInfo = addInfo;
	add(addProfessionInfo);
    }
}