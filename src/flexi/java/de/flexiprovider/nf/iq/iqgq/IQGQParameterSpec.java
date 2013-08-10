package de.flexiprovider.nf.iq.iqgq;

import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.math.FlexiBigInt;

/**
 * This class specifies parameters for the IQGQ signature algorithm (implemented
 * by {@link IQGQSignature}.
 * 
 * @author Ralf-P. Weinmann
 */
public class IQGQParameterSpec implements AlgorithmParameterSpec {

    // the discriminant of the class group
    private FlexiBigInt discriminant;

    /**
     * Construct new IQGQ parameters from the given discriminant of the class
     * group.
     * 
     * @param discriminant
     *                the discriminant of the class group
     */
    public IQGQParameterSpec(FlexiBigInt discriminant) {
	this.discriminant = discriminant;
    }

    /**
     * @return the discriminant of the class group
     */
    public FlexiBigInt getDiscriminant() {
	return discriminant;
    }

    /**
     * Compare these parameters with another object.
     * 
     * @param other
     *                the other object
     * @return the result of the comparison
     */
    public boolean equals(Object other) {
	if (other == null || !(other instanceof IQGQParameterSpec)) {
	    return false;
	}
	IQGQParameterSpec oParamSpec = (IQGQParameterSpec) other;

	return discriminant.equals(oParamSpec.discriminant);
    }

    /**
     * @return the hash code of these parameters
     */
    public int hashCode() {
	return discriminant.hashCode();
    }

}
