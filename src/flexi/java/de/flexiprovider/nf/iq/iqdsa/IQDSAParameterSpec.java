package de.flexiprovider.nf.iq.iqdsa;

import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.math.quadraticfields.QuadraticIdeal;

/**
 * This class specifies parameters for the IQDSA signature algorithm
 * (implemented by {@link IQDSASignature}.
 * 
 * @author Ralf-P. Weinmann
 */
public class IQDSAParameterSpec implements AlgorithmParameterSpec {

    // the discriminant of the class group
    private FlexiBigInt discriminant;

    // the generator of the class group
    private QuadraticIdeal gamma;

    /**
     * Construct new IQDSA parameters from the given discriminant and generator
     * of the class group.
     * 
     * @param discriminant
     *                the discriminant of the class group
     * @param gamma
     *                the generator of the class group
     */
    public IQDSAParameterSpec(FlexiBigInt discriminant, QuadraticIdeal gamma) {
	this.discriminant = discriminant;
	this.gamma = gamma;
    }

    /**
     * @return the discriminant of the class group
     */
    public FlexiBigInt getDiscriminant() {
	return discriminant;
    }

    /**
     * @return the generator of class group
     */
    public QuadraticIdeal getGamma() {
	return gamma;
    }

    /**
     * Compare these parameters with another object.
     * 
     * @param other
     *                the other object
     * @return the result of the comparison
     */
    public boolean equals(Object other) {
	if (!(other instanceof IQDSAParameterSpec)) {
	    return false;
	}
	IQDSAParameterSpec oParams = (IQDSAParameterSpec) other;

	return discriminant.equals(oParams.discriminant)
		&& gamma.equals(oParams.gamma);
    }

    /**
     * @return the hash code of these parameters
     */
    public int hashCode() {
	return discriminant.hashCode() + gamma.hashCode();
    }

}
