package de.flexiprovider.api;

import java.security.AlgorithmParameterGeneratorSpi;
import java.security.AlgorithmParametersSpi;
import java.security.KeyFactorySpi;
import java.security.KeyPairGeneratorSpi;
import java.security.MessageDigestSpi;
import java.security.Provider;
import java.security.SecureRandomSpi;
import java.security.SignatureSpi;

import javax.crypto.CipherSpi;
import javax.crypto.KeyAgreementSpi;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.MacSpi;
import javax.crypto.SecretKeyFactorySpi;

import de.flexiprovider.api.exceptions.RegistrationException;

/**
 * This class is the base class for all providers which are part of the
 * FlexiProvider library. It contains registration methods which provide
 * existence and type checking of the registered classes as well as an improved
 * alias handling.
 * 
 * @author Martin Döring
 */
public abstract class FlexiProvider extends Provider {

    /* algorithm type constants */

    /**
     * Constant for ciphers
     */
    protected static final int CIPHER = 0;

    /**
     * Constant for message authentication codes (MACs)
     */
    protected static final int MAC = 1;

    /**
     * Constant for message digests (hash functions)
     */
    protected static final int MESSAGE_DIGEST = 2;

    /**
     * Constant for PRNGs
     */
    protected static final int SECURE_RANDOM = 3;

    /**
     * Constant for digital signatures
     */
    protected static final int SIGNATURE = 4;

    /**
     * Constant for algorithm parameters (used to encode and decode parameter
     * specifications)
     */
    protected static final int ALG_PARAMS = 5;

    /**
     * Constant for algorithm parameter generators
     */
    protected static final int ALG_PARAM_GENERATOR = 6;

    /**
     * Constant for secret key generators
     */
    protected static final int SECRET_KEY_GENERATOR = 7;

    /**
     * Constant for key pair generators
     */
    protected static final int KEY_PAIR_GENERATOR = 8;

    /**
     * Constant for secret key factories
     */
    protected static final int SECRET_KEY_FACTORY = 9;

    /**
     * Constant for key factories
     */
    protected static final int KEY_FACTORY = 10;

    /**
     * Constant for key agreements
     */
    protected static final int KEY_AGREEMENT = 11;

    // array holding the algorithm type prefixes (indexed by algorithm type)
    private static final String[] prefixes = { "Cipher.", "Mac.",
	    "MessageDigest.", "SecureRandom.", "Signature.",
	    "AlgorithmParameters.", "AlgorithmParameterGenerator.",
	    "KeyGenerator.", "KeyPairGenerator.", "SecretKeyFactory.",
	    "KeyFactory.", "KeyAgreement." };

    // array holding all algorithm types (used for registration type checking)
    private static final Class[] algClasses = { CipherSpi.class, MacSpi.class,
	    MessageDigestSpi.class, SecureRandomSpi.class, SignatureSpi.class,
	    AlgorithmParametersSpi.class, AlgorithmParameterGeneratorSpi.class,
	    KeyGeneratorSpi.class, KeyPairGeneratorSpi.class,
	    SecretKeyFactorySpi.class, KeyFactorySpi.class,
	    KeyAgreementSpi.class };

    /**
     * Construct a provider with the specified name, version number, and
     * provider information.
     * 
     * @param name
     *                the provider name
     * 
     * @param version
     *                the provider version number
     * 
     * @param info
     *                a description of the provider and its services
     */
    protected FlexiProvider(String name, double version, String info) {
	super(name, version, info);
    }

    /**
     * Register an algorithm of the given type under the given name.
     * 
     * @param type
     *                the algorithm type
     * @param algClass
     *                the class implementing the algorithm
     * @param algName
     *                the name for the algorithm
     * @throws RegistrationException
     *                 if the expected and actual algorithm types do not match
     *                 or an algorithm is already registered under the given
     *                 name.
     */
    protected void add(int type, Class algClass, String algName)
	    throws RegistrationException {
	add(type, algClass, new String[] { algName });
    }

    /**
     * Register an algorithm of the given type under the given names.
     * 
     * @param type
     *                the algorithm type
     * @param algClass
     *                the class implementing the algorithm
     * @param algNames
     *                the names for the algorithm
     * @throws RegistrationException
     *                 if the expected and actual algorithm types do not match
     *                 or an algorithm is already registered under one of the
     *                 given names.
     */
    protected void add(int type, Class algClass, String[] algNames)
	    throws RegistrationException {

	String prefix = getPrefix(type);
	// trivial cases
	if ((prefix == null) || (algClass == null) || (algNames == null)
		|| (algNames.length == 0)) {
	    return;
	}

	// type checking
	Class expClass = algClasses[type];
	if (!expClass.isAssignableFrom(algClass)) {
	    throw new RegistrationException(
		    "expected and actual algorithm types do not match");
	}

	// register first name
	put(prefix + algNames[0], algClass.getName());

	// register additional names (aliases)
	for (int i = 1; i < algNames.length; i++) {
	    put("Alg.Alias." + prefix + algNames[i], algNames[0]);
	}
    }

    /**
     * Assign an OID for the reverse mapping (OID -> algorithm name) to an
     * algorithm. Check whether the algorithm the OID is assigned to is
     * registered.
     * 
     * @param type
     *                the algorithm type
     * @param algName
     *                the algorithm name
     * @param oid
     *                the OID used for reverse mapping
     * @throws RegistrationException
     *                 if the algorithm the OID is assigned to is not
     *                 registered.
     */
    protected void addReverseOID(int type, String algName, String oid)
	    throws RegistrationException {
	// get prefix
	String prefix = getPrefix(type);
	if (prefix == null) {
	    // unknown type
	    return;
	}

	// check if algorithm is registered
	Object alg = get(prefix + algName);
	if (alg == null) {
	    throw new RegistrationException("no such algorithm: " + algName);
	}

	// register reverse OID alias
	put("Alg.Alias." + prefix + "OID." + oid, algName);
    }

    private static String getPrefix(int type) {
	if (type > prefixes.length) {
	    return null;
	}
	return prefixes[type];
    }

}
