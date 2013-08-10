/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.ec.keys;

import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.keys.KeyPair;
import de.flexiprovider.api.keys.KeyPairGenerator;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.math.ellipticcurves.Point;
import de.flexiprovider.common.math.ellipticcurves.ScalarMult;
import de.flexiprovider.ec.parameters.CurveParams;
import de.flexiprovider.ec.parameters.CurveRegistry;

/**
 * This class is used to generate pairs of EC public and private keys. Let <i>G</i>
 * be an <i>Generator</i> with <i>order r</i>, where r is a positiv prime and
 * divides the number of the points of the elliptic curve <i>E</i>. That means,
 * G generates the subgroup of points of E with order r. Then the <i>private key</i>
 * is defined to be <nobr><i>s</i>, <i>1 &lt; s &lt; r</i></nobr> and the
 * <i>public key</i> is defined to be <nobr><i>W = s * G</i></nobr>.
 * 
 * @see ECPublicKey
 * @see ECPrivateKey
 * @author Birgit Henhapl
 */
public class ECKeyPairGenerator extends KeyPairGenerator {

    /**
     * The default key size (192 bits)
     */
    public static final int DEFAULT_KEY_SIZE = 192;

    // the EC domain parameters
    private CurveParams curveParams;

    // the source of randomness
    private SecureRandom mRandom = null;

    // array of precomputed powers of the base point
    private Point[] mOddPowers = null;

    // curve group order
    private FlexiBigInt r;

    // curve group order bit length
    private int rLength;

    // flag indicating whether the key pair generator has been initialized
    private boolean initialized;

    /**
     * Initialize the key pair generator with the given parameter set (which has
     * to be an instance of {@link CurveParams}) and source of randomness. If
     * the parameters are <tt>null</tt>, the default parameters for the
     * {@link #DEFAULT_KEY_SIZE} are used.
     * 
     * @param params
     *                the parameters
     * @param random
     *                the source of randomness
     * @throws InvalidAlgorithmParameterException
     *                 if the parameters are not an instance of
     *                 {@link CurveParams}.
     */
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
	    throws InvalidAlgorithmParameterException {

	if (params == null) {
	    initialize(DEFAULT_KEY_SIZE, random);
	    return;
	}

	if (!(params instanceof CurveParams)) {
	    throw new InvalidAlgorithmParameterException("unsupported type");
	}

	curveParams = (CurveParams) params;
	r = curveParams.getR();
	rLength = r.bitLength();
	mOddPowers = ScalarMult.pre_oddpowers(curveParams.getG(), 4);
	mRandom = (random != null) ? random : Registry.getSecureRandom();

	initialized = true;
    }

    /**
     * Initialize the key pair generator with a key size and source of
     * randomness. Default curves are registered for certain key sizes. The
     * given key size is rounded up to the next registered key size and the
     * corresponding curve is chosen. In effect, the bit length of the group
     * order of the chosen curve is greater than or equal to the specified key
     * size.
     * 
     * @param keySize
     *                the key size in bits
     * @param random
     *                the source of randomness
     * @throws RuntimeException
     *                 if the key size is too large and no default curve exist
     *                 for the specified key size.
     */
    public void initialize(int keySize, SecureRandom random) {
	CurveParams params;
	try {
	    String paramName = CurveRegistry.getDefaultCurveParams(keySize);
	    params = (CurveParams) Registry.getAlgParamSpec(paramName);
	} catch (InvalidAlgorithmParameterException e) {
	    // no default curve exists
	    throw new RuntimeException(e.getMessage());
	}

	try {
	    initialize(params, random);
	} catch (InvalidAlgorithmParameterException e) {
	    // the parameters are correct and must be accepted
	    throw new RuntimeException("internal error");
	}
    }

    private void initializeDefault() {
	initialize(DEFAULT_KEY_SIZE, Registry.getSecureRandom());
    }

    /**
     * Generate a key pair. The key pair consists of the private key, a
     * FlexiBigInt <tt>s</tt> in the interval <tt>[1, r-1]</tt>, and the
     * public key <tt>W</tt>, a point of the elliptic curve <tt>E</tt> over
     * the field <tt>GF(q)</tt>. It is computed as <tt>W = s * G</tt>,
     * where <tt>G</tt>, together with <tt>E, q</tt> and <tt>r</tt> are
     * EC domain parameters.
     * 
     * @return the generated EC key pair
     * @see CurveParams
     * @see ECPublicKey
     * @see ECPrivateKey
     */
    public KeyPair genKeyPair() {
	if (!initialized) {
	    initializeDefault();
	}

	// find statistically unique and unpredictable integer s in the
	// interval [1, r - 1]
	FlexiBigInt s;
	do {
	    s = new FlexiBigInt(rLength, mRandom);
	} while ((s.compareTo(FlexiBigInt.ONE) < 0) || (s.compareTo(r) >= 0));

	// create new ECPrivateKey with value s
	ECPrivateKey privKey = new ECPrivateKey(s, curveParams);

	// create new ECPublicKey with value W = sQ
	ECPublicKey pubKey = new ECPublicKey(ScalarMult.eval_SquareMultiply(
		ScalarMult.determineNaf(s, 4), mOddPowers), curveParams);

	// return the keypair
	return new KeyPair(pubKey, privKey);
    }

}
