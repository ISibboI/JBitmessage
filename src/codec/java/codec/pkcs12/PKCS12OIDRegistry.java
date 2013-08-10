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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1Type;
import codec.asn1.AbstractOIDRegistry;
import codec.asn1.OIDRegistry;

/**
 * This class maps ASN.1 object identifiers onto ASN.1 types suitable for
 * decoding the structure defined by the given OID.
 * 
 * @author Michele Boivin
 * @author Volker Roth
 * @version "$Id: PKCS12OIDRegistry.java,v 1.5 2004/09/23 12:17:17 pebinger Exp $"
 */

public class PKCS12OIDRegistry extends AbstractOIDRegistry {
    /**
     * The base name of files that map OIDs to the names of classes that
     * represent and implement the ASN.1 structure with the respective OIDs.
     */
    public static final String RN = "codec/pkcs12";

    /**
     * The mapping from OID to ASN.1 types implementing encoding and decoding of
     * the ASN.1 structure registered under the given OID.
     * <p>
     * 
     * This field is initialized on the first call to method
     * {@link #getOIDMap getOIDMap()}.
     */
    static private Map map_ = Collections.synchronizedMap(new HashMap());

    static {
	loadOIDMap(map_, RN);
    }

    /**
     * The default PKCS#12 OID registry. This instance calls the global registry
     * if a requested OID could not be found locally.
     */
    static private PKCS12OIDRegistry default_ = new PKCS12OIDRegistry(
	    OIDRegistry.getGlobalOIDRegistry());

    /**
     * Creates an instance of this class with no parent.
     */
    public PKCS12OIDRegistry() {
	this(null);
    }

    /**
     * Creates an instance with the given parent.
     * 
     * @param parent
     *                the parent OID registry.
     */
    public PKCS12OIDRegistry(OIDRegistry parent) {
	super(parent);

    }

    /**
     * Returns the mapping from OID to ASN.1 types. Types may be given as a
     * string representing the postfix of the class name implementing the type,
     * or a class object. If the mapping contains a string then this string is
     * replaced by the corresponding class when this type is first referenced.
     * <p>
     * 
     * The map must always be the same since it might be modified as described
     * above.
     * 
     * @return The OID to class (name) mapping.
     */
    protected Map getOIDMap() {
	return map_;
    }

    /**
     * Returns the prefix that is prepended to strings in the mapping returned
     * by {@link #getOIDMap getOIDMap()} in order to form the fully qualified
     * class name.
     * 
     * @return The prefix of class names in the mapping.
     */
    protected String getPrefix() {
	return RN;
    }

    /**
     * Retrieves an ASN.1 type for the given OID or <code>null</code> if no
     * such type was found.
     * 
     */
    protected ASN1Type getLocalASN1Type(ASN1ObjectIdentifier oid) {
	return getLocalASN1Type(oid, map_);
    }

    /**
     * This method returns the default PKCS#12 OID registry. The default
     * registry delegates to the global OID registry if a requested OID could
     * not be found locally.
     * 
     * @return The default PKCS#12 OID registry.
     */
    static public OIDRegistry getDefaultRegistry() {
	return default_;
    }

    public static void main(String[] argv) {
	OIDRegistry reg;
	int n;

	try {
	    reg = PKCS12OIDRegistry.getDefaultRegistry();

	    for (n = 0; n < argv.length; n++) {
		System.out.println(reg.getASN1Type(new ASN1ObjectIdentifier(
			argv[n])));
	    }
	} catch (Exception e) {
	    e.printStackTrace(System.err);
	}
    }
}
