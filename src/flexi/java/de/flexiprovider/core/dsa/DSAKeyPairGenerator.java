/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */
package de.flexiprovider.core.dsa;

import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.keys.KeyPair;
import de.flexiprovider.api.parameters.AlgorithmParameterGenerator;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.core.dsa.interfaces.DSAParams;

/**
 * This class implements the
 * {@link de.flexiprovider.core.dsa.interfaces.DSAKeyPairGenerator} interface.
 * The key pair generation follows the proposal of the <a
 * href="http://csrc.nist.gov/fips/fips186-2.pdf">FIPS 186-2 standard</a>,
 * except for the generation of the random numbers.
 * <p>
 * The default bit length of the prime <tt>p</tt> is 1024 bits.
 * 
 * @author Thomas Wahrenbruch
 */
public class DSAKeyPairGenerator extends
		de.flexiprovider.core.dsa.interfaces.DSAKeyPairGenerator {

	// DSA parameters
	private DSAParams params;

	// source of randomness
	private SecureRandom random;

	// flag indicating whether the key pair generator has been initialized
	private boolean initialized;

	/**
	 * Initialize the key pair generator with the given parameters (supposed to
	 * be an instance of {@link DSAParams}) and source of randomness. If the
	 * parameters are <tt>null</tt>, new parameters are generated for the
	 * {@link DSAParamGenParameterSpec#DEFAULT_L default size} using the
	 * {@link DSAParameterGenerator}.
	 * 
	 * @param params
	 *            the algorithm parameters
	 * @param random
	 *            the source of randomness
	 * @throws InvalidAlgorithmParameterException
	 *             if the parameters are not an instance of {@link DSAParams}.
	 */
	public void initialize(AlgorithmParameterSpec params, SecureRandom random)
			throws InvalidAlgorithmParameterException {

		this.random = (random != null) ? random : Registry.getSecureRandom();

		// if no parameters are specified
		if (params == null) {
			// generate parameters for the default key size
			initialize(DSAParamGenParameterSpec.DEFAULT_L, this.random);
			return;
		}

		if (!(params instanceof DSAParams)) {
			throw new InvalidAlgorithmParameterException("unsupported type");
		}
		this.params = (DSAParams) params;

		initialized = true;
	}

	/**
	 * Initialize the key pair generator with the given strength (bit length of
	 * the prime <tt>p</tt>) and source of randomness.
	 * <p>
	 * If the given strength is not a multiple of 64, the next smaller multiple
	 * of 64 is used as strength. If strength is &gt; 1024 or &lt; 512, 1024 is
	 * used as strength.
	 * <p>
	 * A new parameter set is generated for the chosen strength using the
	 * {@link DSAParameterGenerator} and the given source of randomness.
	 * 
	 * @param keySize
	 *            the bit length of the prime <tt>p</tt>
	 * @param random
	 *            the source of randomness
	 */
	public void initialize(int keySize, SecureRandom random) {
		// generate parameters for the chosen key size
		DSAParamGenParameterSpec genParams = new DSAParamGenParameterSpec(
				keySize);
		AlgorithmParameterGenerator paramGenerator = new DSAParameterGenerator();
		try {
			paramGenerator.init(genParams, random);
			AlgorithmParameterSpec dsaParams = paramGenerator
					.generateParameters();
			initialize(dsaParams, random);
		} catch (InvalidAlgorithmParameterException e) {
			// the parameters are correct and must be accepted
			throw new RuntimeException("internal error");
		}
	}

	private void initializeDefault() {
		// generate parameters for the default key size
		initialize(DSAParamGenParameterSpec.DEFAULT_L, Registry
				.getSecureRandom());
	}

	/**
	 * Generate a key pair, containing a {@link DSAPublicKey} and a
	 * {@link DSAPrivateKey}.
	 * 
	 * @return the generated key pair
	 */
	public KeyPair genKeyPair() {
		if (!initialized) {
			initializeDefault();
		}

		FlexiBigInt p = params.getPrimeP();
		FlexiBigInt q = params.getPrimeQ();
		FlexiBigInt g = params.getBaseG();

		int N = q.bitLength();

		// generate the private x with 0 < x < q
		FlexiBigInt x;
		do {
			x = new FlexiBigInt(N, random);
		} while (x.compareTo(FlexiBigInt.ZERO) == 0 || x.compareTo(q) >= 0);

		// compute the public y
		FlexiBigInt y = g.modPow(x, p);

		DSAPublicKey pubKey = new DSAPublicKey(y, params);
		DSAPrivateKey privKey = new DSAPrivateKey(x, params);

		return new KeyPair(pubKey, privKey);
	}

}
