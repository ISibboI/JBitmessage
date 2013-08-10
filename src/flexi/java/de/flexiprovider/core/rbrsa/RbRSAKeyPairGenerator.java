/*
 * Copyright (c) 1998-2007 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */
package de.flexiprovider.core.rbrsa;

import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.keys.KeyPair;
import de.flexiprovider.api.keys.KeyPairGenerator;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.core.rsa.RSAPrivateCrtKey;
import de.flexiprovider.core.rsa.RSAPublicKey;

/**
 * This class is used to generate key pairs for the rebalanced RSA algorithm. It
 * can be initialized with an instance of {@link RbRSAKeyGenParameterSpec} or
 * with a key size. The key size translates directly to the bit length of the
 * modulus <tt>n = p*q</tt>. The key pair generation follows the PKCS #1
 * standard.
 * 
 * @author Paul Nguentcheu
 * @author Martin Döring
 */
public class RbRSAKeyPairGenerator extends KeyPairGenerator {

    // the certainty that the generated numbers are prime.
    private static final int CERTAINTY = 80;

    private static final FlexiBigInt TWO = FlexiBigInt.valueOf(2);

    // the bit length of the modulus n = p*q.
    private int keySize;

    // the bit length of the private exponent d modulo p and modulo q
    private int s;

    // the source of randomness
    private SecureRandom random;

    // flag indicating whether the key pair generator has been initialized
    private boolean initialized;

    /**
     * Initialize the key pair generator with the given parameters and source of
     * randomness. If the parameters are <tt>null</tt>, the
     * {@link RbRSAKeyGenParameterSpec#RbRSAKeyGenParameterSpec() default parameters}
     * are used.
     * 
     * @param params
     *                the parameters
     * @param random
     *                the source of randomness
     * @throws InvalidAlgorithmParameterException
     *                 if the parameters are not an instance of
     *                 {@link RbRSAKeyGenParameterSpec}.
     */
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
	    throws InvalidAlgorithmParameterException {

	RbRSAKeyGenParameterSpec rsaParams;
	if (params == null) {
	    rsaParams = new RbRSAKeyGenParameterSpec();
	} else if (params instanceof RbRSAKeyGenParameterSpec) {
	    rsaParams = (RbRSAKeyGenParameterSpec) params;
	} else {
	    throw new InvalidAlgorithmParameterException("unsupported type");
	}

	keySize = rsaParams.getKeySize();
	s = rsaParams.getPrivExpSize();
	this.random = random != null ? random : Registry.getSecureRandom();

	initialized = true;
    }

    /**
     * Initialize the key pair generator with the given key size and source of
     * randomness.
     * 
     * @param keySize
     *                the key size
     * @param random
     *                the source of randomness
     */
    public void initialize(int keySize, SecureRandom random) {
	RbRSAKeyGenParameterSpec params = new RbRSAKeyGenParameterSpec();
	try {
	    initialize(params, random);
	} catch (InvalidAlgorithmParameterException e) {
	    // the parameters are correct and must be accepted
	    throw new RuntimeException("internal error");
	}
    }

    private void initializeDefault() {
	RbRSAKeyGenParameterSpec defaultParams = new RbRSAKeyGenParameterSpec();
	try {
	    initialize(defaultParams, Registry.getSecureRandom());
	} catch (InvalidAlgorithmParameterException e) {
	    // the parameters are correct and must be accepted
	    throw new RuntimeException("internal error");
	}
    }

    /**
     * Generate a new rebalanced RSA key pair, consisting of an
     * {@link RSAPrivateCrtKey} and an {@link RSAPublicKey}.
     * 
     * @return the generated key pair
     */
    public KeyPair genKeyPair() {
	if (!initialized) {
	    initializeDefault();
	}

	int bitsp = (keySize + 1) >> 1;
	int bitsq = keySize - bitsp;
	FlexiBigInt p, q, n;

	do {
	    // initial try to get primes
	    p = new FlexiBigInt(bitsp, CERTAINTY, random);
	    do {
		q = new FlexiBigInt(bitsq, CERTAINTY, random);
	    } while ((p.equals(q))
		    || !((p.subtract(FlexiBigInt.ONE)).gcd(q
			    .subtract(FlexiBigInt.ONE)).equals(TWO)));
	    n = p.multiply(q);
	} while (n.bitLength() != keySize);

	FlexiBigInt pm, qm;
	pm = p.subtract(FlexiBigInt.ONE);
	qm = q.subtract(FlexiBigInt.ONE);

	FlexiBigInt d, dp, dq, phi;
	do {
	    do {
		dp = new FlexiBigInt(s, CERTAINTY, random);
	    } while (dp.gcd(pm).intValue() != 1);

	    FlexiBigInt r = dp.mod(TWO);
	    do {
		dq = new FlexiBigInt(s, CERTAINTY, random);
	    } while ((dq.gcd(qm).intValue() != 1)
		    || (dq.mod(TWO).intValue() != r.intValue()));

	    FlexiBigInt m1 = pm.divide(TWO);
	    FlexiBigInt m2 = qm.divide(TWO);
	    FlexiBigInt a1 = dp.subtract(r).divide(TWO);
	    FlexiBigInt a2 = dq.subtract(r).divide(TWO);
	    FlexiBigInt m = m1.multiply(m2);

	    FlexiBigInt tmp = (m2.modInverse(m1).multiply(m2)).multiply(a1)
		    .mod(m);
	    tmp = tmp.add((m1.modInverse(m2).multiply(m1)).multiply(a2).mod(m));

	    d = tmp.multiply(TWO).add(r);
	    phi = pm.multiply(qm);
	} while (!(d.gcd(phi).equals(FlexiBigInt.ONE)));

	FlexiBigInt e = d.modInverse(phi);
	FlexiBigInt crt = q.modInverse(p);
	RSAPublicKey pubKey = new RSAPublicKey(n, e);
	RSAPrivateCrtKey privKey = new RSAPrivateCrtKey(n, d, e, p, q, dp, dq,
		crt);

	return new KeyPair(pubKey, privKey);
    }

}
