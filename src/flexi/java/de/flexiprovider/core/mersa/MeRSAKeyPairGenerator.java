/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */
package de.flexiprovider.core.mersa;

import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.keys.KeyPair;
import de.flexiprovider.api.keys.KeyPairGenerator;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.core.rsa.RSAPublicKey;

/**
 * This class is used to generate key pairs for the multi-exponent RSA
 * algorithms. It can be initialized with an instance of
 * {@link MeRSAKeyGenParameterSpec} or with the bit length of the modulus
 * <tt>n</tt>. The default bit length of the modulus is 1024.
 * 
 * @author Erik Dahmen
 * @author Paul Nguentcheu
 * @author Martin Döring
 */
public class MeRSAKeyPairGenerator extends KeyPairGenerator {

    // the certainty that the generated numbers are prime
    private final int CERTAINTY = 80;

    private static final FlexiBigInt TWO = FlexiBigInt.valueOf(2);

    // the bit length of the modulus n = p^k*q.
    private int keySize;

    // the encryption/verification exponent
    private FlexiBigInt e;

    // the exponent of the prime p
    private int k;

    // the source of randomness
    private SecureRandom random;

    // flag indicating whether the key pair generator has been initialized
    private boolean initialized;

    /**
     * Initialize the key pair generator with the given parameters and source of
     * randomness. If the parameters are <tt>null</tt>, the
     * {@link MeRSAKeyGenParameterSpec#MeRSAKeyGenParameterSpec() default parameters}
     * are used.
     * 
     * @param params
     *                the parameters
     * @param random
     *                the source of randomness
     * @throws InvalidAlgorithmParameterException
     *                 if the parameters are not an instance of
     *                 {@link MeRSAKeyGenParameterSpec}.
     */
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
	    throws InvalidAlgorithmParameterException {

	MeRSAKeyGenParameterSpec rsaParams;
	if (params == null) {
	    rsaParams = new MeRSAKeyGenParameterSpec();
	} else if (params instanceof MeRSAKeyGenParameterSpec) {
	    rsaParams = (MeRSAKeyGenParameterSpec) params;
	} else {
	    throw new InvalidAlgorithmParameterException("unsupported type");
	}

	keySize = rsaParams.getKeySize();
	e = rsaParams.getE();
	k = rsaParams.getExponentK();
	this.random = random != null ? random : Registry.getSecureRandom();

	initialized = true;
    }

    /**
     * Initialize the key pair generator with the given key size and source of
     * randomness.
     * 
     * @param keySize
     *                the bit length of the prime p
     * @param secureRand
     *                the source of randomness.
     */
    public void initialize(int keySize, SecureRandom secureRand) {
	MeRSAKeyGenParameterSpec params = new MeRSAKeyGenParameterSpec(keySize);
	try {
	    initialize(params, Registry.getSecureRandom());
	} catch (InvalidAlgorithmParameterException e) {
	    // the parameters are correct and must be accepted
	    throw new RuntimeException("internal error");
	}
    }

    private void initializeDefault() {
	MeRSAKeyGenParameterSpec defaultParams = new MeRSAKeyGenParameterSpec();
	try {
	    initialize(defaultParams, Registry.getSecureRandom());
	} catch (InvalidAlgorithmParameterException e) {
	    // the parameters are correct and must be accepted
	    throw new RuntimeException("internal error");
	}
    }

    /**
     * Generate a MeRSA key pair, consisting of a {@link MeRSAPrivateKey} and an
     * {@link RSAPublicKey}.
     * 
     * @return the generated key pair
     */
    public KeyPair genKeyPair() {
	if (!initialized) {
	    initializeDefault();
	}

	int pBitSize = keySize / (k + 1);
	int qBitSize = keySize - pBitSize * k;

	FlexiBigInt p, q, n;
	do {
	    p = new FlexiBigInt(pBitSize, CERTAINTY, random);
	    do {
		q = new FlexiBigInt(qBitSize, CERTAINTY, random);
	    } while (p.equals(q));
	    n = p.pow(k).multiply(q);
	} while (n.bitLength() != keySize);

	FlexiBigInt k_ = FlexiBigInt.valueOf(k);

	FlexiBigInt lcm = (p.subtract(FlexiBigInt.ONE)).multiply(q
		.subtract(FlexiBigInt.ONE));
	lcm = lcm.divide(p.subtract(FlexiBigInt.ONE).gcd(
		q.subtract(FlexiBigInt.ONE)));

	while (!e.gcd(p).equals(FlexiBigInt.ONE)
		|| !e.gcd(lcm).equals(FlexiBigInt.ONE)) {
	    e = e.add(TWO);
	}

	FlexiBigInt d = e.modInverse(lcm);
	FlexiBigInt dp = d.mod(p.subtract(FlexiBigInt.ONE));
	FlexiBigInt dq = d.mod(q.subtract(FlexiBigInt.ONE));
	FlexiBigInt e_inv_p = e.modInverse(p);
	FlexiBigInt pk_inv_q = (p.pow(k)).modInverse(q);

	RSAPublicKey pubKey = new RSAPublicKey(n, e);
	MeRSAPrivateKey privKey = new MeRSAPrivateKey(n, e, d, p, q, dp, dq,
		pk_inv_q, k_, e_inv_p);

	return new KeyPair(pubKey, privKey);
    }

}
