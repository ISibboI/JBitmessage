/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 */
package de.flexiprovider.nf.iq.iqrdsa;

import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.parameters.AlgorithmParameterGenerator;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.api.parameters.AlgorithmParameters;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.math.IntegerFunctions;
import de.flexiprovider.common.math.quadraticfields.IQClassGroup;

/**
 * This class implements the IQRDSAAlgorithmParameterGenerator.
 * <p>
 * The default bit length of the discriminant of the class group is 768 bits.
 * 
 * @author Martin Döring
 */
public class IQRDSAParameterGenerator extends AlgorithmParameterGenerator {

    private static final FlexiBigInt primeBound = FlexiBigInt.ONE
	    .shiftLeft(160);

    // the bit length of the discriminant
    private int size;

    // the source of randomness
    private SecureRandom random;

    // flag indicating whether the parameter generator has been initialized
    private boolean initialized;

    /**
     * @return an instance of the {@link AlgorithmParameters} class
     *         corresponding to the generated parameters
     */
    protected AlgorithmParameters getAlgorithmParameters() {
	return new IQRDSAParameters();
    }

    /**
     * Initialize the parameter generator with parameters and a source of
     * randomness. If the parameters are <tt>null</tt>, the
     * {@link IQRDSAParamGenParameterSpec#IQRDSAParamGenParameterSpec() default parameters}
     * are used.
     * 
     * @param genParams
     *                the parameters
     * @param random
     *                the source of randomness
     * @throws InvalidAlgorithmParameterException
     *                 if the parameters are not an instance of
     *                 {@link IQRDSAParamGenParameterSpec}.
     */
    public void init(AlgorithmParameterSpec genParams, SecureRandom random)
	    throws InvalidAlgorithmParameterException {

	IQRDSAParamGenParameterSpec iqdsaGenParams;
	if (genParams == null) {
	    iqdsaGenParams = new IQRDSAParamGenParameterSpec();
	} else if (genParams instanceof IQRDSAParamGenParameterSpec) {
	    iqdsaGenParams = (IQRDSAParamGenParameterSpec) genParams;
	} else {
	    throw new InvalidAlgorithmParameterException("unsupported type");
	}

	size = iqdsaGenParams.getSize();
	this.random = random != null ? random : Registry.getSecureRandom();

	initialized = true;
    }

    /**
     * Initialize the parameter generator with the size of the prime <tt>p</tt>
     * and a source of randomness.
     * <p>
     * If the bit length of the discriminant is &lt; 2, the
     * {@link IQRDSAParamGenParameterSpec#DEFAULT_SIZE} is used as bit length.
     * If the bit length is &gt; {@link IQRDSAParamGenParameterSpec#MAX_SIZE},
     * {@link IQRDSAParamGenParameterSpec#MAX_SIZE} is used as bit length.
     * 
     * @param size
     *                the bit length of the discriminant (&gt;= 2, &lt;=
     *                {@link IQRDSAParamGenParameterSpec#MAX_SIZE})
     * @param random
     *                the source of randomness
     */
    public void init(int size, SecureRandom random) {
	IQRDSAParamGenParameterSpec genParams = new IQRDSAParamGenParameterSpec(
		size);
	try {
	    init(genParams, random);
	} catch (InvalidAlgorithmParameterException e) {
	    // the parameters are correct and must be accepted
	    throw new RuntimeException("internal error");
	}
    }

    private void initDefault() {
	IQRDSAParamGenParameterSpec defaultGenParams = new IQRDSAParamGenParameterSpec();
	try {
	    init(defaultGenParams, Registry.getSecureRandom());
	} catch (InvalidAlgorithmParameterException e) {
	    // the parameters are correct and must be accepted
	    throw new RuntimeException("internal error");
	}
    }

    /**
     * Generate IQRDSA algorithm parameters.
     * 
     * @return the generated IQRDSA parameters
     * 
     * @see IQRDSAParameterSpec
     */
    public AlgorithmParameterSpec generateParameters() {
	if (!initialized) {
	    initDefault();
	}

	// p: random prime in the interval n/2 ... n
	FlexiBigInt nHalves = primeBound.shiftRight(1);
	FlexiBigInt p = IntegerFunctions.nextProbablePrime(nHalves
		.add(IntegerFunctions.randomize(nHalves, random)));

	IQClassGroup classGroup = new IQClassGroup(size, true, random);
	FlexiBigInt discriminant = classGroup.getDiscriminant();

	return new IQRDSAParameterSpec(discriminant, p);
    }

}
