/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group, Technische Universitaet
 * Darmstadt
 * 
 * For conditions of usage and distribution please refer to the file COPYING in
 * the root directory of this package.
 * 
 */
package de.flexiprovider.core.elgamal.semanticallysecure;

import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.keys.KeyPair;
import de.flexiprovider.api.keys.KeyPairGenerator;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.math.IntegerFunctions;

/**
 * This class is used to generate key pairs for the semantically secure variant
 * of the ElGamal encryption algorithm (implemented by {@link SSVElGamal}). It
 * can be initialized with the bit length of the prime <tt>p</tt>. The default
 * bit length of the prime <tt>p</tt> is 1024 bits.
 * 
 * @author Thomas Wahrenbruch
 * @author Martin Döring
 * @author Roberto Samarone dos Santos Araújo
 * 
 */
public class SSVElGamalKeyPairGenerator extends KeyPairGenerator {


	// the certainty that the generated numbers are prime
	private static final int CERTAINTY = 80;

	private static final FlexiBigInt TWO = FlexiBigInt.valueOf(2);
	private static final FlexiBigInt MINUSONE = FlexiBigInt.valueOf(-1);

	// the bit length of the prime p
	private int keySize = 1024;

	// the source of randomness
	private SecureRandom random;

	// flag indicating whether the key pair generator has been initialized
	private boolean initialized;

	/**
	 * Initialize the key pair generator with the specified parameters and
	 * source of randomness. If the parameters are <tt>null</tt>, the
	 * {@link SSVElGamalKeyGenParameterSpec#ElGamalKeyGenParameterSpec() default
	 * parameters} are used.
	 * 
	 * @param params
	 *            the parameters
	 * @param random
	 *            the source of randomness
	 * @throws InvalidAlgorithmParameterException
	 *             if the parameters are not an instance of
	 *             {@link SSVElGamalKeyGenParameterSpec}.
	 */
	public void initialize(AlgorithmParameterSpec params, SecureRandom random)
			throws InvalidAlgorithmParameterException {

		SSVElGamalKeyGenParameterSpec elGamalParams;
		if (params == null) {
			elGamalParams = new SSVElGamalKeyGenParameterSpec();
		} else if (params instanceof SSVElGamalKeyGenParameterSpec) {
			elGamalParams = (SSVElGamalKeyGenParameterSpec) params;
		} else {
			throw new InvalidAlgorithmParameterException("unsupported type");
		}

		keySize = elGamalParams.getKeySize();
		this.random = random != null ? random : Registry.getSecureRandom();

		initialized = true;
	}

	/**
	 * Initialize the key pair generator with the specified key size and source
	 * of randomness.
	 * 
	 * @param keySize
	 *            the bit length of the prime <tt>p</tt>
	 * @param random
	 *            the source of randomness
	 */
	public void initialize(int keySize, SecureRandom random) {
		SSVElGamalKeyGenParameterSpec params = new SSVElGamalKeyGenParameterSpec(
				keySize);
		try {
			initialize(params, random);
		} catch (InvalidAlgorithmParameterException e) {
			// the parameters are correct and must be accepted
			throw new RuntimeException("internal error");
		}
	}

	private void initializeDefault() {
		SSVElGamalKeyGenParameterSpec defaultParams = new SSVElGamalKeyGenParameterSpec();
		try {
			initialize(defaultParams, Registry.getSecureRandom());
		} catch (InvalidAlgorithmParameterException e) {
			// the parameters are correct and must be accepted
			throw new RuntimeException("internal error");
		}
	}

	/**
	 * Generate a key pair, containing an {@link SSVElGamalPublicKey} and an
	 * {@link SSVElGamalPrivateKey}.
	 * <p>
	 * The prime <tt>p</tt> is always of the form <tt>2*q+1</tt>. The algorithm
	 * generates a prime number <tt>q</tt> and computes <tt>p = 2*q+1</tt> until
	 * <tt>p</tt> is prime. Then, a generator of the group <tt>(Z/pZ)*</tt> is
	 * generated. In the last step, a random number <tt>a</tt> with
	 * <tt>0 < a < p-2</tt>, is chosen. The public key parameters are
	 * <tt>A = g<sup>a</sup> mod p</tt>, <tt>p</tt>, and <tt>g</tt>. The private
	 * key parameters are <tt>a</tt>, <tt>p</tt>, and <tt>g</tt>.
	 * 
	 * @return the generated key pair
	 */
	public KeyPair genKeyPair() {
		if (!initialized) {
			initializeDefault();
		}

		/*
		 * Implements an algorithm to find a strong prime. A strong prime p is
		 * given, if <tt>p = 2p'+1</tt> and p' is also prime (Sophie Germain
		 * prime). This algorithm implements the suggestion of Cramer Shoup,
		 * "Signature Schemes based on the strong RSA assumption", 2000.
		 */

		FlexiBigInt germainPrime;
		FlexiBigInt strongPrime;

		do {
			FlexiBigInt two2GermainPrime;
			do {
				do {
					do {
						do {
							germainPrime = new FlexiBigInt(keySize - 1, random);
							strongPrime = (germainPrime.shiftLeft(1))
									.add(FlexiBigInt.ONE);
						} while (strongPrime.bitLength() != keySize);
					} while (!IntegerFunctions
							.passesSmallPrimeTest(germainPrime)
							|| !IntegerFunctions
									.passesSmallPrimeTest(strongPrime));
				} while (!germainPrime.isProbablePrime(CERTAINTY));
				two2GermainPrime = TWO.modPow(germainPrime, strongPrime);
			} while (!two2GermainPrime.equals(FlexiBigInt.ONE)
					&& !two2GermainPrime.subtract(strongPrime).equals(MINUSONE));
		} while (!germainPrime.isProbablePrime(CERTAINTY));

		FlexiBigInt p = strongPrime;
		FlexiBigInt q = germainPrime;

		// find a generator
		FlexiBigInt g, gPowTwo, gPowQ;
		do {
			g = new FlexiBigInt(keySize - 1, random);
			gPowTwo = g.modPow(TWO, p);
			gPowQ = g.modPow(q, p);
		} while (gPowTwo.equals(FlexiBigInt.ONE)
				|| gPowQ.equals(FlexiBigInt.ONE) || g.equals(FlexiBigInt.ZERO)
				|| g.equals(FlexiBigInt.ONE));

		g = gPowTwo;

		FlexiBigInt pMinusOne = p.subtract(FlexiBigInt.ONE);

		FlexiBigInt a;
		do {
			a = new FlexiBigInt(keySize, random);
		} while ((a.compareTo(pMinusOne)) >= 0);

		FlexiBigInt A = g.modPow(a, p);

		SSVElGamalPublicKey pub = new SSVElGamalPublicKey(p, q, g, A);
		SSVElGamalPrivateKey priv = new SSVElGamalPrivateKey(p, q, g, A, a);

		return new KeyPair(pub, priv);
	}

}
