/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */
package de.flexiprovider.core.rprimersa;

import java.util.Vector;

import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.keys.KeyPair;
import de.flexiprovider.api.keys.KeyPairGenerator;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.core.mprsa.MpRSAPrivateKey;
import de.flexiprovider.core.mprsa.RSAOtherPrimeInfo;
import de.flexiprovider.core.rsa.RSAPublicKey;

/**
 * This class is used to generate key pairs for the rebalanced multi-prime RSA
 * algorithm. It can be initialized with an instance of
 * {@link RprimeRSAKeyGenParameterSpec} or with a key size. The key size
 * translates directly to the bit length of the modulus <tt>n = p*q</tt>. The
 * key pair generation follows the PKCS #1 standard.
 * 
 * @author Paul Nguentcheu
 * @author Martin Döring
 */
public class RprimeRSAKeyPairGenerator extends KeyPairGenerator {

    // the certainty, that the generated numbers are prime
    private static final int CERTAINTY = 80;

    private static final FlexiBigInt TWO = FlexiBigInt.valueOf(2);

    // the bit length of the modulus n
    private int keySize;

    // the number of primes
    private int k;

    // the bit length of the private exponent d modulo all primes
    private int s;

    // the source of randomness
    private SecureRandom random;

    // flag indicating whether the key pair generator has been initialized
    private boolean initialized;

    /**
     * Initialize the key pair generator with the given parameters and source of
     * randomness. If the parameters are <tt>null</tt>, the
     * {@link RprimeRSAKeyGenParameterSpec#RprimeRSAKeyGenParameterSpec() default parameters}
     * are used.
     * 
     * @param params
     *                an AlgorithmParameterSpec object
     * @param secureRand
     *                the source of randomness
     * @throws InvalidAlgorithmParameterException
     *                 if the parameters are not an instance of
     *                 {@link RprimeRSAKeyGenParameterSpec}.
     */
    public void initialize(AlgorithmParameterSpec params,
	    SecureRandom secureRand) throws InvalidAlgorithmParameterException {

	RprimeRSAKeyGenParameterSpec rsaParams;
	if (params == null) {
	    rsaParams = new RprimeRSAKeyGenParameterSpec();
	} else if (params instanceof RprimeRSAKeyGenParameterSpec) {
	    rsaParams = (RprimeRSAKeyGenParameterSpec) params;
	} else {
	    throw new InvalidAlgorithmParameterException("unsupported type");
	}

	keySize = rsaParams.getKeySize();
	k = rsaParams.getNumPrimes();
	s = rsaParams.getPrivExpSize();
	this.random = secureRand != null ? secureRand : Registry
		.getSecureRandom();

	initialized = true;
    }

    /**
     * Initialize the key pair generator with the given key size and source of
     * randomness.
     * 
     * @param keySize
     *                the bit length of the modulus <tt>n</tt>
     * @param random
     *                the source of randomness
     */
    public void initialize(int keySize, SecureRandom random) {
	RprimeRSAKeyGenParameterSpec params = new RprimeRSAKeyGenParameterSpec(
		keySize);
	try {
	    initialize(params, random);
	} catch (InvalidAlgorithmParameterException e) {
	    // the parameters are correct and must be accepted
	    throw new RuntimeException("internal error");
	}
    }

    private void initializeDefault() {
	RprimeRSAKeyGenParameterSpec defaultParams = new RprimeRSAKeyGenParameterSpec();
	try {
	    initialize(defaultParams, Registry.getSecureRandom());
	} catch (InvalidAlgorithmParameterException e) {
	    // the parameters are correct and must be accepted
	    throw new RuntimeException("internal error");
	}
    }

    /**
     * Generate a multi-prime RSA key pair.
     * 
     * @return the key pair, consisting of an {@link MpRSAPrivateKey} and an
     *         {@link RSAPublicKey}
     */
    public KeyPair genKeyPair() {
	if (!initialized) {
	    initializeDefault();
	}

	int pBitSize = (keySize + 1) / k;
	int qBitSize = pBitSize;
	int rnBitSize = keySize - (k - 1) * pBitSize;

	Vector v;
	FlexiBigInt p, q, n, d, phi;
	FlexiBigInt[] otherPrime;
	do {
	    // generate primes p and q
	    p = new FlexiBigInt(pBitSize, CERTAINTY, random);
	    do {
		q = new FlexiBigInt(qBitSize, CERTAINTY, random);

	    } while ((p.equals(q))
		    || !((p.subtract(FlexiBigInt.ONE)).gcd(q
			    .subtract(FlexiBigInt.ONE)).equals(TWO)));

	    v = new Vector();
	    v.addElement(p);
	    v.addElement(q);
	    // generate primes with the bit length bitsp.
	    otherPrime = new FlexiBigInt[k - 2];
	    for (int i = 0; i < otherPrime.length - 1; i++) {
		otherPrime[i] = new FlexiBigInt(pBitSize, CERTAINTY, random);
		if (contains(v, otherPrime[i]) || (!gcdIs2(otherPrime[i], v))) {
		    i--;
		} else {
		    v.addElement(otherPrime[i]);
		}
	    }
	    // generate the last prime with the bit length bitrn.
	    do {
		otherPrime[otherPrime.length - 1] = new FlexiBigInt(rnBitSize,
			CERTAINTY, random);
	    } while (contains(v, otherPrime[otherPrime.length - 1])
		    || (!gcdIs2(otherPrime[otherPrime.length - 1], v)));

	    v.addElement(otherPrime[otherPrime.length - 1]);
	    n = p.multiply(q);
	    // compute n
	    for (int i = 0; i < otherPrime.length; i++) {
		n = n.multiply(otherPrime[i]);
	    }

	} while (n.bitLength() != keySize);

	FlexiBigInt[] pm = new FlexiBigInt[k];
	// compute p-1 for each prime p.
	for (int i = 0; i < k; i++) {
	    pm[i] = ((FlexiBigInt) v.elementAt(i)).subtract(FlexiBigInt.ONE);
	}

	FlexiBigInt[] dp = new FlexiBigInt[k];
	do {
	    dp[0] = new FlexiBigInt(s, CERTAINTY, random);
	} while (!(dp[0].gcd(pm[0]).equals(FlexiBigInt.ONE)));

	FlexiBigInt r = dp[0].mod(TWO);
	FlexiBigInt[] ai, mi;
	do {
	    for (int i = 1; i < k; i++) {
		do {
		    dp[i] = new FlexiBigInt(s, CERTAINTY, random);
		} while (!(dp[i].gcd(pm[i]).equals(FlexiBigInt.ONE))
			|| !(dp[i].mod(TWO).equals(r)));
	    }

	    // Chinese remainder theorem m = ai mod (mi) 0 <= i <= k
	    ai = new FlexiBigInt[k];
	    mi = new FlexiBigInt[k];
	    FlexiBigInt m = FlexiBigInt.ONE;
	    for (int i = 0; i < k; i++) {
		ai[i] = dp[i].subtract(r).divide(TWO);
		mi[i] = pm[i].divide(TWO);
		m = m.multiply(mi[i]);
	    }

	    // Use of CRT to compute the private exponent d
	    // m = ai mod (mi) 0 <= i <= k
	    d = FlexiBigInt.ZERO;
	    for (int i = 0; i < k; i++) {
		FlexiBigInt Mi = m.divide(mi[i]);
		FlexiBigInt y = Mi.modInverse(mi[i]);
		d = d.add(y.multiply(Mi).multiply(ai[i])).mod(m);
	    }

	    d = d.multiply(TWO).add(r);
	    phi = lcm(pm);
	} while (!(d.gcd(phi).equals(FlexiBigInt.ONE)));

	// compute exponent e and other exponents.
	FlexiBigInt e_ = d.modInverse(phi);
	FlexiBigInt exponentOne = dp[0];
	FlexiBigInt exponentTwo = dp[1];
	FlexiBigInt crt = q.modInverse(p);
	RSAOtherPrimeInfo[] otherPrimeInfo = new RSAOtherPrimeInfo[k - 2];

	FlexiBigInt R = (FlexiBigInt) v.elementAt(0);
	for (int i = 0; i < otherPrimeInfo.length; i++) {
	    R = R.multiply((FlexiBigInt) v.elementAt(i + 1));
	    otherPrimeInfo[i] = new RSAOtherPrimeInfo(otherPrime[i], dp[i + 2],
		    R.modInverse(otherPrime[i]));
	}

	RSAPublicKey pubKey = new RSAPublicKey(n, e_);
	MpRSAPrivateKey privKey = new MpRSAPrivateKey(n, d, e_, p, q,
		exponentOne, exponentTwo, crt, otherPrimeInfo);

	return new KeyPair(pubKey, privKey);
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
     * Check if the gcd of a-1 and x-1 is 2. x is an element of the array v.
     * 
     * @param a
     *                the first number
     * @param v
     *                the vector whose first element is <tt>x</tt>
     * @return the result of the check <tt>gcd(a-1, x-1) == 2</tt>
     */
    private boolean gcdIs2(FlexiBigInt a, Vector v) {
	FlexiBigInt one = FlexiBigInt.ONE;
	FlexiBigInt tmp = a.subtract(one).gcd(
		((FlexiBigInt) v.elementAt(0)).subtract(one));
	boolean b = tmp.intValue() == 2;

	for (int i = 1; (i < v.size()) && b; i++) {
	    tmp = a.subtract(one).gcd(
		    ((FlexiBigInt) v.elementAt(i)).subtract(one));
	    b = tmp.intValue() == 2;
	}
	return b;
    }

}
