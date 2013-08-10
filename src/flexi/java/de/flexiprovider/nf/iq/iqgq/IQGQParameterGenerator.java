/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 */
package de.flexiprovider.nf.iq.iqgq;

import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.parameters.AlgorithmParameterGenerator;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.api.parameters.AlgorithmParameters;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.math.quadraticfields.IQClassGroup;

/**
 * This class is used to generate parameters for the IQGQ signature algorithm.
 * 
 * @author Martin Döring
 */
public class IQGQParameterGenerator extends AlgorithmParameterGenerator {

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
	return new IQGQParameters();
    }

    /**
     * Initialize the parameter generator with parameters and a source of
     * randomness. If the parameters are <tt>null</tt>, the
     * {@link IQGQParamGenParameterSpec#IQGQParamGenParameterSpec() default parameters}
     * are used.
     * 
     * @param genParams
     *                the parameters
     * @param random
     *                the source of randomness
     * @throws InvalidAlgorithmParameterException
     *                 if the parameters are not an instance of
     *                 {@link IQGQParamGenParameterSpec}.
     */
    public void init(AlgorithmParameterSpec genParams, SecureRandom random)
	    throws InvalidAlgorithmParameterException {

	IQGQParamGenParameterSpec iqdsaGenParams;
	if (genParams == null) {
	    iqdsaGenParams = new IQGQParamGenParameterSpec();
	} else if (genParams instanceof IQGQParamGenParameterSpec) {
	    iqdsaGenParams = (IQGQParamGenParameterSpec) genParams;
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
     * {@link IQGQParamGenParameterSpec#DEFAULT_SIZE} is used as bit length. If
     * the bit length is &gt; {@link IQGQParamGenParameterSpec#MAX_SIZE},
     * {@link IQGQParamGenParameterSpec#MAX_SIZE} is used as bit length.
     * 
     * @param size
     *                the bit length of the discriminant (&gt;= 2, &lt;=
     *                {@link IQGQParamGenParameterSpec#MAX_SIZE})
     * @param random
     *                the source of randomness
     */
    public void init(int size, SecureRandom random) {
	IQGQParamGenParameterSpec genParams = new IQGQParamGenParameterSpec(
		size);
	try {
	    init(genParams, random);
	} catch (InvalidAlgorithmParameterException e) {
	    // the parameters are correct and must be accepted
	    throw new RuntimeException("internal error");
	}
    }

    private void initDefault() {
	IQGQParamGenParameterSpec defaultGenParams = new IQGQParamGenParameterSpec();
	try {
	    init(defaultGenParams, Registry.getSecureRandom());
	} catch (InvalidAlgorithmParameterException e) {
	    // the parameters are correct and must be accepted
	    throw new RuntimeException("internal error");
	}
    }

    /**
     * Generate IQGQ algorithm parameters.
     * 
     * @return the generated IQGQ parameters
     * @see IQGQParameterSpec
     */
    public AlgorithmParameterSpec generateParameters() {
	if (!initialized) {
	    initDefault();
	}

	IQClassGroup classGroup = new IQClassGroup(size, true, random);
	FlexiBigInt discriminant = classGroup.getDiscriminant();
	return new IQGQParameterSpec(discriminant);
    }

}
