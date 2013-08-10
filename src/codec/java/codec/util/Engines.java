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
package codec.util;

import java.security.Provider;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * This class provides the standard JCA/JCE engine name associations. The names
 * defined in the JCA and JCE specification documents can be retrieved by engine
 * as well as the engine names themselves. This class is primarily informative
 * but can be used to check the definitions of providers for adherence of Sun's
 * naming scheme.
 * <p>
 * 
 * The algorithm names, in particular the ciphers, are extended by some
 * algorithm names not defined in the original documents but whose algorithms
 * are implemented by multiple providers in a way suggesting uniform
 * understanding on the name. Examples are RC2 and RC5.
 * 
 * @author Volker Roth
 * @version "$Id: Engines.java,v 1.2 2000/12/06 17:47:34 vroth Exp $"
 */
public class Engines extends Object {
    /**
     * The names of Cipher instances. I added RC2 and RC5 and RSA which do not
     * appear in the standard.
     */
    protected static String[] cipher_ = { "DES", "DESede", "Blowfish", "RC2",
	    "RC5", "PBEWithMD5AndDES", "RSA" };

    /**
     * The names of the KeyGenerator instances. Please note that PBE is not
     * included since passwords are chosen by users and are not generated.
     */
    protected static String[] keyGenerator_ = { "DES", "DESede", "Blowfish",
	    "RC2", "RC5" };

    /**
     * The names of the KeyPairGenerator instances.
     */
    protected static String[] keyPairGenerator_ = { "RSA", "DSA",
	    "DiffieHellman" };

    /**
     * The names of the KeyAgreement instances. DiffieHellman is defined in
     * PKCS#3.
     */
    protected static String[] keyAgreement_ = { "DiffieHellman" };

    /**
     * The names of the KeyGenerator instances. Please note that PBE is not
     * included since passwords are chosen by users and are not generated.
     */
    protected static String[] secretKeyFactory_ = { "DES", "DESede",
	    "Blowfish", "RC2", "RC5", "PBE" };

    protected static String[] keyFactory_ = { "DiffieHellman", "RSA", "DSA" };

    /**
     * The names of the AlgorithmParameters instances.
     */
    protected static String[] algorithmParameters_ = { "DES", "DESede",
	    "Blowfish", "RC2", "RC5", "PBE", "DiffieHellman", "RSA", "DSA" };

    /**
     * The names of the AlgorithmParameterGenerator instances. The JCE specifies
     * only DiffieHellman at this point. In order to allow algorithm-independent
     * initialization of ciphers parameter generators for almost all ciphers
     * should be provided.
     */
    protected static String[] algorithmParameterGenerator_ = { "DES", "DESede",
	    "Blowfish", "RC2", "RC5", "PBE", "DiffieHellman", "RSA", "DSA" };

    /**
     * The names of the Mac instances. HmacMD5 and HmacSHA1 are defined in RFC
     * 2104. No OIDs are defined in this RFC.
     */
    protected static String[] mac_ = { "HmacMD5", "HmacSHA1" };

    /**
     * The names of the KeyStore instances. These names are basically up to the
     * provider since no particular implementations or characteristics are
     * associated with a particular keystore name.
     */
    protected static String[] keyStore_ = { "JCEKS", "JKS", "PKCS12" };

    /**
     * The names of the MessageDigest instances.
     */
    protected static String[] messageDigest_ = { "SHA", "MD2", "MD5" };

    /**
     * The names of the Signature instances. SHA1WithDSA is specified in FIPS
     * PUB 186.
     */
    protected static String[] signature_ = { "SHA1withDSA", "MD2withRSA",
	    "MD5withRSA", "SHA1withRSA" };

    /**
     * The names of the SecureRandom instances. The SHA1PRNG follows IEEE P1363.
     */
    protected static String[] secureRandom_ = { "SHA1PRNG" };

    /**
     * The names of the CertificateFactory instances.
     */
    protected static String[] certificateFactory_ = { "X509" };

    /**
     * The names of the cipher operation modes. No engines correspond to these
     * names.
     */
    protected static String[] mode_ = { "ECB", "CBC", "CFB", "OFB", "PCBC" };

    /**
     * The names of the padding algorithms. No engines correspond to these
     * names.
     */
    protected static String[] padding_ = { "NoPadding", "PKCS5Padding",
	    "SSL3Padding" };

    /**
     * The names of the standard engines.
     */
    protected static String[] engines_ = { "AlgorithmParameterGenerator",
	    "AlgorithmParameters", "MessageDigest", "KeyFactory",
	    "KeyPairGenerator", "Signature", "SecureRandom",
	    "CertificateFactory", "Cipher", "KeyGenerator", "SecretKeyFactory",
	    "Mac", "KeyStore", "KeyAgreement" };

    /**
     * The well-known standardised engine names.
     */
    protected static Map map_;

    /**
     * No-one may instantiate this class.
     */
    private Engines() {
    }

    /**
     * Initializes the names of the JCE/JCA engines.
     */
    protected static Map initEngines() {
	HashMap map;

	map = new HashMap();
	map.put("messagedigest", messageDigest_);
	map.put("keyfactory", keyFactory_);
	map.put("keypairgenerator", keyPairGenerator_);
	map.put("algorithmparametergenerator", algorithmParameterGenerator_);
	map.put("algorithmparameters", algorithmParameters_);
	map.put("signature", signature_);
	map.put("securerandom", secureRandom_);
	map.put("certificatefactory", certificateFactory_);
	map.put("cipher", cipher_);
	map.put("keygenerator", keyGenerator_);
	map.put("secretkeyfactory", secretKeyFactory_);
	map.put("keyagreement", keyAgreement_);
	map.put("mac", mac_);
	map.put("keystore", keyStore_);

	return map;
    }

    /**
     * Retrieves the standard names defined in the JCE and JCA for the given
     * engine type.
     * 
     * @param engine
     *                The name of the engine type of which the standard names
     *                should be returned.
     * @return The list of standard algorithm names for the given engine type.
     */
    public static List getStdNames(String engine) {
	int i;
	List list;
	String[] names;

	if (map_ == null) {
	    map_ = initEngines();
	}
	if (engine == null)
	    throw new NullPointerException("Engine is NULL!");

	names = (String[]) map_.get(engine.toLowerCase());
	if (names == null)
	    throw new IllegalStateException("Illegal engine name (" + engine
		    + ")");

	list = new ArrayList(names.length);
	for (i = 0; i < names.length; i++)
	    list.add(names[i]);

	return list;
    }

    /**
     * Returns a list of the valid engine names defined in the JCA and JCE in no
     * particular order.
     * 
     * @return The list of engine names.
     */
    public static List getEngineNames() {
	int i;
	List list;

	list = new ArrayList(engines_.length);
	for (i = 0; i < engines_.length; i++)
	    list.add(engines_[i]);

	return list;
    }

    /**
     * Returns the list of names of the engines of the given type that are
     * declared by the given provider.
     * 
     * @param p
     *                The provider from which the names are taken.
     * @param engine
     *                The engine name.
     * @return The list of names declared by the given provider for the given
     *         engine type.
     */
    public static List getEngineNames(Provider p, String engine) {
	ArrayList list;
	Iterator i;
	String s;
	String u;

	if (p == null || engine == null || engine.length() == 0)
	    throw new NullPointerException("Need a provider and engine name!");

	list = new ArrayList();
	engine = engine.toLowerCase() + ".";

	for (i = p.keySet().iterator(); i.hasNext();) {
	    s = (String) i.next();
	    u = s.toLowerCase();

	    if (u.startsWith(engine)) {
		u = s.substring(engine.length());
		if (u.length() > 0)
		    list.add(u);
	    }
	}
	list.trimToSize();

	return list;
    }
}
