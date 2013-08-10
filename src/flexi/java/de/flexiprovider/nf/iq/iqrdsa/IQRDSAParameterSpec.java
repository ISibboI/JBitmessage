package de.flexiprovider.nf.iq.iqrdsa;

import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.math.FlexiBigInt;

/**
 * This class specifies parameters for the IQRDSA signature algorithm
 * (implemented by {@link IQRDSASignature}).
 * 
 * @author Ralf-P. Weinmann
 */
public class IQRDSAParameterSpec implements AlgorithmParameterSpec {

    // the discriminant of the class group
    private FlexiBigInt discriminant;

    // the modulus
    private FlexiBigInt modulus;

    /**
     * Construct new IQRDSA parameters from the given discriminant of the class
     * group and modulus.
     * 
     * @param discriminant
     *                the discriminant of the class group
     * @param modulus
     *                the modulus
     */
    public IQRDSAParameterSpec(FlexiBigInt discriminant, FlexiBigInt modulus) {
	this.discriminant = discriminant;
	this.modulus = modulus;
    }

    /**
     * @return the discriminant of the class group
     */
    public FlexiBigInt getDiscriminant() {
	return discriminant;
    }

    /**
     * @return the modulus
     */
    public FlexiBigInt getModulus() {
	return modulus;
    }

    /**
     * Compare these parameters with another object.
     * 
     * @param other
     *                the other object
     * @return the result of the comparison
     */
    public boolean equals(Object other) {
	if (other == null || !(other instanceof IQRDSAParameterSpec)) {
	    return false;
	}
	IQRDSAParameterSpec oParamSpec = (IQRDSAParameterSpec) other;

	return discriminant.equals(oParamSpec.discriminant)
		&& modulus.equals(oParamSpec.modulus);
    }

    /**
     * @return the hash code of these parameters
     */
    public int hashCode() {
	return discriminant.hashCode() + modulus.hashCode();
    }

}
