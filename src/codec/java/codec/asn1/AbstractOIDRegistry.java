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
package codec.asn1;

import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;

/**
 * This class maps ASN.1 object identifiers onto ASN.1 types suitable for
 * decoding the structure defined by the given OID.
 * 
 * @author Volker Roth
 */
public abstract class AbstractOIDRegistry extends OIDRegistry {
    /**
     * Loads the OID mappings of this registry into the given Map. OID mappings
     * are defined in OID definition files which are loaded from the
     * <code>CLASSPATH</code>. OID definition files are simple properties
     * files which map an OID to the name of the class which implements the
     * structure identifier by that OID.
     * 
     * <p>
     * The name of such files is <code>oid</code><i>n</i><code>.map</code>
     * where <i>n</i> is a running count starting from 0. All files with
     * consecutive numbering are loaded.
     * </p>
     * 
     * @param map
     *                The map to load to.
     * @param path
     *                The path relativ to the class path from which the mappings
     *                are loaded.
     */
    protected static void loadOIDMap(Map map, String path) {
	loadOIDMap2(map, "codec/asn1");
	loadOIDMap2(map, path);
    }

    /**
     * Returns the prefix that is prepended to strings in the mapping returned
     * by {@link #getOIDMap getOIDMap()} in order to form the fully qualified
     * class name.
     * 
     * @return The prefix of class names in the mapping.
     */
    protected abstract String getPrefix();

    /**
     * DOCUMENT ME!
     * 
     * @param map
     *                DOCUMENT ME!
     * @param path
     *                DOCUMENT ME!
     */
    private static void loadOIDMap2(Map map, String path) {
	ASN1ObjectIdentifier oid;
	InputStream in;
	Properties props;
	Iterator i;
	String key;
	String val;
	int n;

	if ((map == null) || (path == null)) {
	    throw new NullPointerException("map or path");
	}

	n = 0;
	in = ClassLoader.getSystemResourceAsStream(path + "/oid0.map");

	// trying different loaders and paths
	if (in == null) {
	    in = AbstractOIDRegistry.class.getResourceAsStream(path
		    + "/oid0.map");

	    if (in == null) {
		in = AbstractOIDRegistry.class.getResourceAsStream("/" + path
			+ "/oid0.map");

		if (in == null) {
		    System.out.println("Warning: could not get resource at "
			    + path);
		}
	    }
	}

	while (in != null) {
	    try {
		props = new Properties();
		props.load(in);

		for (i = props.keySet().iterator(); i.hasNext();) {
		    key = (String) i.next();

		    if (key.indexOf(';') != -1) {
			// remove additional information required
			// only by codec.gen
			key = key.substring(0, key.indexOf(';'));
		    }

		    if (key.endsWith(".")) {
			// ignore properties with improper OID
			// these OID are needed by codec.gen
			// The generator has additional information
			// from ASN.1 module definitions
			// to proceed with this OIDs
			continue;
		    }

		    val = props.getProperty(key);
		    oid = new ASN1ObjectIdentifier(key.trim());

		    map.put(oid, val);
		}
	    } catch (IOException e) {
		System.err
			.println("Bad OID map: " + path + "/oid" + n + ".map");
	    } finally {
		try {
		    in.close();
		} catch (IOException e) {
		    System.err.println(e.getMessage());
		}
	    }
	    n++;
	    in = ClassLoader.getSystemResourceAsStream(path + "/oid" + n
		    + ".map");
	}
	if (map.size() == 0) {
	    System.err.println("Warning: no OIDs loaded from " + path);
	}
    }

    /**
     * Creates an OID registry.
     */
    public AbstractOIDRegistry() {
	this(null);
    }

    /**
     * Creates an OID registry with the given parent. If an OID is not found by
     * this registry then the search is delegated to the parent registry.
     * 
     * @param parent
     *                The parent OID registry.
     */
    public AbstractOIDRegistry(OIDRegistry parent) {
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
    protected abstract Map getOIDMap();

    /**
     * Retrieves an ASN.1 type for the given OID or <code>null</code> if no
     * such type was found.
     * 
     * @param oid
     *                The OID
     * @return The ASN.1 type for the given OID
     */
    protected ASN1Type getLocalASN1Type(ASN1ObjectIdentifier oid) {
	Object o;
	Class c;
	Map map;
	map = getOIDMap();
	o = map.get(oid);
	if (o == null) {
	    return null;
	}
	try {
	    if (o instanceof String) {
		c = Class.forName(getPrefix() + (String) o);
		map.put(new ASN1ObjectIdentifier(oid.getOID()), c);
		o = c;
	    }
	    c = (Class) o;

	    return (ASN1Type) c.newInstance();
	} catch (Exception e) {
	    e.printStackTrace();
	    return null;
	}
    }
}
