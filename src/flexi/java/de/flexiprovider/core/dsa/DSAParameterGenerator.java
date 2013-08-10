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
import de.flexiprovider.api.parameters.AlgorithmParameterGenerator;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.api.parameters.AlgorithmParameters;
import de.flexiprovider.common.math.FlexiBigInt;

/**
 * This class implements the DSAAlgorithmParameterGenerator. The parameter
 * generation follows the proposal of the <a
 * href="http://csrc.nist.gov/fips/fips186-2.pdf">FIPS 186-2 standard</a>,
 * except for the generation of the random numbers.
 * <p>
 * The default bit length of the prime <tt>p</tt> is 1024 bits.
 * 
 * @author Thomas Wahrenbruch
 */
public class DSAParameterGenerator extends AlgorithmParameterGenerator {

    /**
     * The OID of DSA.
     */
    public static final String OID = DSAKeyFactory.OID;

    /**
     * An alternative OID of DSA.
     */
    public static final String OID2 = DSAKeyFactory.OID2;

    // certainties for prime number generation
    private static final int LO_CERTAINTY = 20;
    private static final int HI_CERTAINTY = 80;

    private static final FlexiBigInt TWO = FlexiBigInt.valueOf(2);

    // the source of randomness
    private SecureRandom random;

    // the bit length of the prime p
    private int L;

    // the bit length of the subprime q
    private int N;

    // flag indicating whether the parameter generator has been initialized
    private boolean initialized;

    /**
     * @return an instance of the {@link AlgorithmParameters} class
     *         corresponding to the generated parameters
     */
    protected AlgorithmParameters getAlgorithmParameters() {
	return new DSAParameters();
    }

    /**
     * Initialize the parameter generator with parameters and a source of
     * randomness. If the parameters are <tt>null</tt>, the
     * {@link DSAParamGenParameterSpec#DSAParamGenParameterSpec() default parameters}
     * are used.
     * 
     * @param genParams
     *                the parameters
     * @param random
     *                the source of randomness
     * @throws InvalidAlgorithmParameterException
     *                 if the parameters are not an instance of
     *                 {@link DSAParamGenParameterSpec}.
     */
    public void init(AlgorithmParameterSpec genParams, SecureRandom random)
	    throws InvalidAlgorithmParameterException {

	DSAParamGenParameterSpec dsaGenParams;
	if (genParams == null) {
	    dsaGenParams = new DSAParamGenParameterSpec();
	} else if (genParams instanceof DSAParamGenParameterSpec) {
	    dsaGenParams = (DSAParamGenParameterSpec) genParams;
	} else {
	    throw new InvalidAlgorithmParameterException("unsupported type");
	}

	L = dsaGenParams.getL();
	N = dsaGenParams.getN();
	this.random = random != null ? random : Registry.getSecureRandom();

	initialized = true;
    }

    /**
     * Initialize the parameter generator with the size of the prime <tt>p</tt>
     * and a source of randomness.
     * <p>
     * If the size is not a multiple of 64, the next smaller multiple of 64 is
     * used as size. If the size is &gt; 1024 or &lt; 512, the
     * {@link DSAParamGenParameterSpec#DEFAULT_L default size} is used.
     * 
     * @param size
     *                the bit length of the prime p
     * @param random
     *                the source of randomness
     */
    public void init(int size, SecureRandom random) {
	DSAParamGenParameterSpec genParams = new DSAParamGenParameterSpec(size);
	try {
	    init(genParams, random);
	} catch (InvalidAlgorithmParameterException e) {
	    // the parameters are correct and must be accepted
	    throw new RuntimeException("internal error");
	}
    }

    private void initDefault() {
	DSAParamGenParameterSpec defaultGenParams = new DSAParamGenParameterSpec();
	try {
	    init(defaultGenParams, Registry.getSecureRandom());
	} catch (InvalidAlgorithmParameterException e) {
	    // the parameters are correct and must be accepted
	    throw new RuntimeException("internal error");
	}
    }

    /**
     * Generate DSA algorithm parameters.
     * 
     * @return the generated DSA parameters
     * 
     * @see DSAParameterSpec
     */
    public AlgorithmParameterSpec generateParameters() {
	if (!initialized) {
	    initDefault();
	}

	// the maximum number of tries to find a prime p given the subprime q
	int maxTries;
	FlexiBigInt q, x, c, p, qMultTwo;

	// TODO: speed up
	out: while (true) {
	    maxTries = 4096;
	    q = new FlexiBigInt(N, HI_CERTAINTY, random);

	    do {
		x = generateX();
		qMultTwo = q.multiply(TWO);
		c = x.mod(qMultTwo);
		p = x.subtract(c).add(FlexiBigInt.ONE);
		// if p is long enough
		if (p.bitLength() >= L) {
		    // do fast primality test
		    if (p.isProbablePrime(LO_CERTAINTY)) {
			// do slow primality tests
			if (p.isProbablePrime(HI_CERTAINTY)) {
			    // p is prime - we're done
			    break out;
			}
		    }
		}
	    } while (--maxTries > 0);
	}

	FlexiBigInt pMinusOne = p.subtract(FlexiBigInt.ONE);
	FlexiBigInt pMinusOneModQ = pMinusOne.divide(q);

	// generate random h with 1 < h < p-1
	FlexiBigInt h, g;
	do {
	    h = new FlexiBigInt(L - 1, random);
	    g = h.modPow(pMinusOneModQ, p);
	} while ((h.compareTo(FlexiBigInt.ONE) <= 0)
		|| (h.compareTo(pMinusOne) >= 0)
		|| (g.compareTo(FlexiBigInt.ONE) <= 0));

	return new DSAParameterSpec(p, q, g);
    }

    /**
     * Generate a random number <tt>r</tt> with
     * <tt>size-1 &lt;= |r| &lt; size</tt>.
     * 
     * @return the generated random number
     */
    private FlexiBigInt generateX() {
	byte[] xBytes = new byte[L >> 3];
	random.nextBytes(xBytes);
	xBytes[0] = (byte) (xBytes[0] | 0x80);

	return new FlexiBigInt(1, xBytes);
    }

}
