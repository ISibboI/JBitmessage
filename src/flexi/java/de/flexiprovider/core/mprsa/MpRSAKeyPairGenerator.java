/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */
package de.flexiprovider.core.mprsa;

import java.util.Vector;

import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.keys.KeyPair;
import de.flexiprovider.api.keys.KeyPairGenerator;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.core.rsa.RSAPublicKey;

/**
 * This class extends the KeyPairGenerator class. A key pair consists of a
 * MpRSAPubKey and a MpRSAPrivKey.
 * <p>
 * The default bit length of n is 1024 bits and the default number of prime is
 * 3.
 * 
 * @author Paul Nguentcheu
 */
public class MpRSAKeyPairGenerator extends KeyPairGenerator {

    // the certainty that the generated numbers are prime.
    private static final int CERTAINTY = 80;

    // the bit length of the modulus n
    private int keySize;

    // the encryption/verification exponent
    private FlexiBigInt e;

    // the number of primes
    private int k;

    // the source of randomness
    private SecureRandom random;

    // flag indicating whether the key pair generator has been initialized
    private boolean initialized;

    /**
     * Initialize the key pair generator with the given parameters and source of
     * randomness. If the parameters are <tt>null</tt>, the
     * {@link MpRSAKeyGenParameterSpec#MpRSAKeyGenParameterSpec() default parameters}
     * are used.
     * 
     * @param params
     *                the parameters
     * @param random
     *                the source of randomness
     * @throws InvalidAlgorithmParameterException
     *                 if the parameters are not an instance of
     *                 {@link MpRSAKeyGenParameterSpec}.
     */
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
	    throws InvalidAlgorithmParameterException {

	MpRSAKeyGenParameterSpec rsaParams;
	if (params == null) {
	    rsaParams = new MpRSAKeyGenParameterSpec();
	} else if (params instanceof MpRSAKeyGenParameterSpec) {
	    rsaParams = (MpRSAKeyGenParameterSpec) params;
	} else {
	    throw new InvalidAlgorithmParameterException("unsupported type");
	}

	keySize = rsaParams.getKeySize();
	e = rsaParams.getE();
	k = rsaParams.getNumPrimes();
	this.random = random != null ? random : Registry.getSecureRandom();

	initialized = true;
    }

    /**
     * Initialize the key pair generator with the given key size and source of
     * randomness.
     * 
     * @param keySize
     *                the bit length of the modulus n
     * @param secureRand
     *                the source of randomness
     */
    public void initialize(int keySize, SecureRandom secureRand) {
	MpRSAKeyGenParameterSpec params = new MpRSAKeyGenParameterSpec();
	try {
	    initialize(params, random);
	} catch (InvalidAlgorithmParameterException e) {
	    // the parameters are correct and must be accepted
	    throw new RuntimeException("internal error");
	}
    }

    private void initializeDefault() {
	MpRSAKeyGenParameterSpec defaultParams = new MpRSAKeyGenParameterSpec();
	try {
	    initialize(defaultParams, Registry.getSecureRandom());
	} catch (InvalidAlgorithmParameterException e) {
	    // the parameters are correct and must be accepted
	    throw new RuntimeException("internal error");
	}
    }

    /**
     * Generate a new multi-prime RSA key pair, consisting of an
     * {@link MpRSAPrivateKey} and an {@link RSAPublicKey}.
     * 
     * @return the generated key pair
     */
    public KeyPair genKeyPair() {
	if (!initialized) {
	    initializeDefault();
	}

	FlexiBigInt p, q, n;
	Vector v;
	FlexiBigInt[] otherPrime = new FlexiBigInt[k - 2];

	int bitsp = (keySize + 1) / k;
	int bitsq = bitsp;
	int bitrn = keySize - (k - 1) * bitsp;

	do {
	    p = new FlexiBigInt(bitsp, CERTAINTY, random);

	    do {
		q = new FlexiBigInt(bitsq, CERTAINTY, random);
	    } while (p.equals(q));

	    v = new Vector();
	    v.addElement(p);
	    v.addElement(q);

	    for (int i = 0; i < otherPrime.length - 1; i++) {
		otherPrime[i] = new FlexiBigInt(bitsp, CERTAINTY, random);
		if (contains(v, otherPrime[i])) {
		    i--;
		} else {
		    v.addElement(otherPrime[i]);
		}
	    }

	    do {
		otherPrime[otherPrime.length - 1] = new FlexiBigInt(bitrn,
			CERTAINTY, random);
	    } while (contains(v, otherPrime[otherPrime.length - 1]));

	    v.addElement(otherPrime[otherPrime.length - 1]);

	    n = p.multiply(q);
	    for (int i = 0; i < otherPrime.length; i++) {
		n = n.multiply(otherPrime[i]);
	    }

	} while (n.bitLength() != keySize);

	FlexiBigInt one = FlexiBigInt.ONE;
	FlexiBigInt[] pm = new FlexiBigInt[k];
	for (int i = 0; i < k; i++) {
	    pm[i] = ((FlexiBigInt) v.elementAt(i)).subtract(one);
	}

	FlexiBigInt phi = lcm(pm);
	FlexiBigInt two = FlexiBigInt.valueOf(2);

	// increase exponent in steps of 2 in case gcd(phi, e) > 1
	while (!(phi.gcd(e)).equals(one)) {
	    e = e.add(two);
	}

	FlexiBigInt d = e.modInverse(phi);
	FlexiBigInt dp = d.mod(pm[0]);
	FlexiBigInt dq = d.mod(pm[1]);
	FlexiBigInt crt = q.modInverse(p);
	RSAOtherPrimeInfo[] otherPrimeInfo = new RSAOtherPrimeInfo[k - 2];

	FlexiBigInt R = (FlexiBigInt) v.elementAt(0);
	for (int i = 0; i < otherPrimeInfo.length; i++) {
	    R = R.multiply((FlexiBigInt) v.elementAt(i + 1));
	    otherPrimeInfo[i] = new RSAOtherPrimeInfo(otherPrime[i], d
		    .mod(pm[i + 2]), R.modInverse(otherPrime[i]));
	}

	RSAPublicKey pubKey = new RSAPublicKey(n, e);
	MpRSAPrivateKey privKey = new MpRSAPrivateKey(n, e, d, p, q, dp, dq,
		crt, otherPrimeInfo);
	// System.out.println("public Key........\n" + pub.toString());
	// System.out.println("private Key........\n" + priv.toString());

	return new KeyPair(pubKey, privKey);
    }

    /**
     * Compute the least common multiple of the elements contained in a vector.
     * 
     * @param v
     *                the vector
     * @return the least common multiple of the elements of the vector
     */
    private FlexiBigInt lcm(FlexiBigInt[] v) {
	FlexiBigInt product = v[0];
	FlexiBigInt gcd_ = product;

	for (int i = 1; i < v.length; i++) {
	    FlexiBigInt tmp = v[i];
	    product = product.multiply(tmp);
	    gcd_ = gcd_.gcd(tmp);
	}
	return product.divide(gcd_);
    }

    /**
     * Check if a vector contains a certain element.
     * 
     * @param v
     *                the vector
     * @param x
     *                the element
     * @return <tt>true</tt> if <tt>v</tt> contains <tt>x</tt>
     */
    private boolean contains(Vector v, FlexiBigInt x) {
	for (int i = 0; i < v.size(); i++) {
	    if (x.equals(v.elementAt(i))) {
		return true;
	    }
	}
	return false;
    }

}
