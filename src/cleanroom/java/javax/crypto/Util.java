/* Copyright 2000 Fraunhofer Gesellschaft
 * Leonrodstr. 54, 80636 Munich, Germany.
 * All rights reserved.
 *
 * You shall use this software only in accordance with
 * the terms of the license agreement you entered into
 * with Fraunhofer Gesellschaft.
 */
package javax.crypto;

import java.security.AccessController;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.util.StringTokenizer;

/**
 * 
 * 
 * @author Patric Kabus
 * @version $Id: Util.java,v 1.1.1.1 2001/05/15 11:59:09 krprvadm Exp $
 */
class Util extends Object {
    public static final String CIPHER = "Cipher";

    public static final String ALIAS_SUFFIX = "Alg.Alias.";

    public static final String KEY_AGREEMENT = "KeyAgreement";

    public static final String KEY_GENERATOR = "KeyGenerator";

    public static final String MAC = "Mac";

    public static final String SECRET_KEY_FACTORY = "SecretKeyFactory";

    static Object[] getImpl(String algorithm, String type)
	    throws NoSuchAlgorithmException {
	Provider[] providers;
	Object[] o;
	int i;

	o = null;
	providers = Security.getProviders();
	for (i = 0; i < providers.length; i++) {
	    try {
		o = getImpl(algorithm, type, providers[i]);

		if (o != null) {
		    return o;
		}
	    } catch (Exception e) {
		/* Not found, try next one. */
	    }
	}
	throw new NoSuchAlgorithmException(algorithm);
    }

    static Object[] getImpl(String algorithm, String type, String provider)
	    throws NoSuchAlgorithmException, NoSuchProviderException {
	Provider prov;

	prov = Security.getProvider(provider);
	if (prov == null) {
	    throw new NoSuchProviderException(provider);
	}
	return getImpl(algorithm, type, prov);
    }

    private static Object[] getImpl(String algorithm, String type,
	    Provider provider) throws NoSuchAlgorithmException {

	Object[] o;

	o = new Object[2];
	o[0] = AccessController.doPrivileged(new GetImplPrivilegedAction(
		algorithm, type, provider));

	if (o[0] == null) {
	    throw new NoSuchAlgorithmException(algorithm);
	}
	o[1] = provider;

	return o;
    }

    static String resolveAlgorithm(String algorithm, String type,
	    Provider provider) {

	String className = null;

	StringTokenizer st = new StringTokenizer(algorithm, "/");
	int cnt = st.countTokens();
	String[] params = new String[cnt];

	for (int i = 0; i < cnt; i++) {
	    params[i] = st.nextToken();
	}

	if (cnt == 3) {
	    className = provider.getProperty(type + "." + params[0] + "/"
		    + params[1] + "/" + params[2]);
	    if (className == null) {
		className = provider.getProperty(ALIAS_SUFFIX + type + "."
			+ params[0] + "/" + params[1] + "/" + params[2]);
		className = provider.getProperty(className == null ? "" : (type
			+ "." + className));
		if (className == null) {
		    cnt--;
		}
	    }

	}

	if (cnt == 2) {
	    className = provider.getProperty(type + "." + params[0] + "/"
		    + params[1]);
	    if (className == null) {
		className = provider.getProperty(ALIAS_SUFFIX + type + "."
			+ params[0] + "/" + params[1]);
		className = provider.getProperty(className == null ? "" : (type
			+ "." + className));
		if (className == null) {
		    cnt--;
		}
	    }

	}

	if (cnt == 1) {
	    className = provider.getProperty(type + "." + params[0]);
	    if (className == null) {
		className = provider.getProperty(ALIAS_SUFFIX + type + "."
			+ params[0]);
		className = provider.getProperty(className == null ? "" : (type
			+ "." + className));
	    }
	}

	return className;
    }
}
