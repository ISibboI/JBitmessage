/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */
package de.flexiprovider.core.rsa;

import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.keys.KeyPair;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.math.FlexiBigInt;

/**
 * This class extends the KeyPairGenerator class. The key generation follows the
 * PKCS#1 standard. The algorithm strength translates directly to the bit length
 * of the modulus <tt>n = p*q</tt>. A key pair consists of an
 * {@link RSAPublicKey} and an {@link RSAPrivateCrtKey}. The default bit length
 * of <tt>n</tt> is 1024.
 * 
 * @author Thomas Wahrenbruch
 * @author Martin Döring
 */
public final class RSAKeyPairGenerator extends
	de.flexiprovider.core.rsa.interfaces.RSAKeyPairGenerator {

    // the certainty that the generated numbers are prime
    private static final int CERTAINTY = 80;

    private static final FlexiBigInt ONE = FlexiBigInt.ONE;

    // the bit length of the modulus
    private int keySize;

    // encryption/verification exponent
    private FlexiBigInt e;

    /**
     * The source of randomness.
     */
    private SecureRandom random = Registry.getSecureRandom();

    // flag indicating whether the key pair generator has been initialized
    private boolean initialized;

    /**
     * Initialize the key pair generator with the given parameters and source of
     * randomness. If the parameters are <tt>null</tt>, the
     * {@link RSAKeyGenParameterSpec#RSAKeyGenParameterSpec() default parameters}
     * are used.
     * 
     * @param params
     *                the key generation parameters
     * @param random
     *                the source of randomness
     * @throws InvalidAlgorithmParameterException
     *                 if the parameters are not an instance of
     *                 {@link RSAKeyGenParameterSpec}.
     */
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
	    throws InvalidAlgorithmParameterException {

	RSAKeyGenParameterSpec rsaParams;
	if (params == null) {
	    rsaParams = new RSAKeyGenParameterSpec();
	} else if (params instanceof RSAKeyGenParameterSpec) {
	    rsaParams = (RSAKeyGenParameterSpec) params;
	} else {
	    throw new InvalidAlgorithmParameterException("unsupported type");
	}

	keySize = rsaParams.getKeySize();
	e = rsaParams.getE();
	this.random = random != null ? random : Registry.getSecureRandom();

	initialized = true;
    }

    /**
     * Initialize the key pair generator with the given key size.
     * 
     * @param keySize
     *                the bit length of the modulus <tt>n</tt>
     * @param random
     *                the source of randomness
     */
    public void initialize(int keySize, SecureRandom random) {
	RSAKeyGenParameterSpec params = new RSAKeyGenParameterSpec(keySize);
	try {
	    initialize(params, random);
	} catch (InvalidAlgorithmParameterException e) {
	    // the parameters are correct and must be accepted
	    throw new RuntimeException("internal error");
	}
    }

    private void initializeDefault() {
	RSAKeyGenParameterSpec defaultParams = new RSAKeyGenParameterSpec();
	try {
	    initialize(defaultParams, Registry.getSecureRandom());
	} catch (InvalidAlgorithmParameterException e) {
	    // the parameters are correct and must be accepted
	    throw new RuntimeException("internal error");
	}
    }

    /**
     * Generate an RSA key pair.
     * 
     * @return the key pair, consisting of an {@link RSAPrivateCrtKey} and an
     *         {@link RSAPublicKey}
     */
    public KeyPair genKeyPair() {
	if (!initialized) {
	    initializeDefault();
	}

	int bitsp = (keySize + 1) >> 1;
	int bitsq = keySize - bitsp;

	FlexiBigInt p, q, n, pm, qm, phi;
	do {
	    // initial try to get primes
	    p = new FlexiBigInt(bitsp, CERTAINTY, random);

	    do {
		q = new FlexiBigInt(bitsq, CERTAINTY, random);
	    } while (p.equals(q));

	    n = p.multiply(q);

	    pm = p.subtract(ONE);
	    qm = q.subtract(ONE);
	    phi = pm.multiply(qm);
	    // get new primes until n has the correct bitlength and the gcd of
	    // phi and e is 1
	} while ((n.bitLength() < keySize) || !(e.gcd(phi).compareTo(ONE) == 0));

	FlexiBigInt d = e.modInverse(phi);
	FlexiBigInt dp = d.mod(pm);
	FlexiBigInt dq = d.mod(qm);
	FlexiBigInt crt = q.modInverse(p);

	RSAPublicKey pubKey = new RSAPublicKey(n, e);
	RSAPrivateCrtKey privKey = new RSAPrivateCrtKey(n, e, d, p, q, dp, dq,
		crt);

	return new KeyPair(pubKey, privKey);
    }

}
