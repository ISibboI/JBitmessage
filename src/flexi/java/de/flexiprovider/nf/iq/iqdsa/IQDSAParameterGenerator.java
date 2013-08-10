/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 */
package de.flexiprovider.nf.iq.iqdsa;

import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.parameters.AlgorithmParameterGenerator;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.api.parameters.AlgorithmParameters;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.math.quadraticfields.IQClassGroup;
import de.flexiprovider.common.math.quadraticfields.QuadraticIdeal;

/**
 * This class is used to generate parameters for the IQDSA signature algorithm.
 * 
 * @author Martin Döring
 */
public class IQDSAParameterGenerator extends AlgorithmParameterGenerator {

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
	return new IQDSAParameters();
    }

    /**
     * Initialize the parameter generator with parameters (supposed to be an
     * instance of {@link IQDSAParamGenParameterSpec}) and a source of
     * randomness. If the parameters are <tt>null</tt>, the
     * {@link IQDSAParamGenParameterSpec#IQDSAParamGenParameterSpec() default parameters}
     * are used.
     * 
     * @param genParams
     *                the parameters
     * @param random
     *                the source of randomness
     * @throws InvalidAlgorithmParameterException
     *                 if the parameters are not an instance of
     *                 {@link IQDSAParamGenParameterSpec}.
     */
    public void init(AlgorithmParameterSpec genParams, SecureRandom random)
	    throws InvalidAlgorithmParameterException {

	IQDSAParamGenParameterSpec iqdsaGenParams;
	if (genParams == null) {
	    iqdsaGenParams = new IQDSAParamGenParameterSpec();
	} else if (genParams instanceof IQDSAParamGenParameterSpec) {
	    iqdsaGenParams = (IQDSAParamGenParameterSpec) genParams;
	} else {
	    throw new InvalidAlgorithmParameterException("unsupported type");
	}

	size = iqdsaGenParams.getSize();
	this.random = random != null ? random : Registry.getSecureRandom();

	initialized = true;
    }

    /**
     * Initialize the parameter generator with the bit length of the
     * discriminant and a source of randomness.
     * <p>
     * If the bit length of the discriminant is &lt; 2, the
     * {@link IQDSAParamGenParameterSpec#DEFAULT_SIZE default size} is used as
     * bit length. If the bit length is &gt;
     * {@link IQDSAParamGenParameterSpec#MAX_SIZE},
     * {@link IQDSAParamGenParameterSpec#MAX_SIZE} is used as bit length.
     * 
     * @param size
     *                the bit length of the discriminant (&gt;= 2, &lt;=
     *                {@link IQDSAParamGenParameterSpec#MAX_SIZE})
     * @param random
     *                the source of randomness
     */
    public void init(int size, SecureRandom random) {
	IQDSAParamGenParameterSpec genParams = new IQDSAParamGenParameterSpec(
		size);
	try {
	    init(genParams, random);
	} catch (InvalidAlgorithmParameterException e) {
	    // the parameters are correct and must be accepted
	    throw new RuntimeException("internal error");
	}
    }

    private void initDefault() {
	IQDSAParamGenParameterSpec defaultGenParams = new IQDSAParamGenParameterSpec();
	try {
	    init(defaultGenParams, Registry.getSecureRandom());
	} catch (InvalidAlgorithmParameterException e) {
	    // the parameters are correct and must be accepted
	    throw new RuntimeException("internal error");
	}
    }

    /**
     * Generate IQDSA algorithm parameters.
     * 
     * @return the generated IQDSA parameters
     * @see IQDSAParameterSpec
     */
    public AlgorithmParameterSpec generateParameters() {
	if (!initialized) {
	    initDefault();
	}

	IQClassGroup classGroup = new IQClassGroup(size, true, random);
	FlexiBigInt discriminant = classGroup.getDiscriminant();
	// gamma: randomly pick an element of the class group
	QuadraticIdeal gamma = classGroup.randomIdeal();
	return new IQDSAParameterSpec(discriminant, gamma);
    }

}
