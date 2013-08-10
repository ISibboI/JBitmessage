/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */
package de.flexiprovider.core.rsa;

import de.flexiprovider.api.parameters.AlgorithmParameterSpec;

/**
 * This class specifies parameters for RSA-OAEP (implemented by
 * {@link RSA_PKCS1_v2_1}). The parameters consist of the OIDs of a hash
 * function, mask generation function, and PSource algorithm.
 * <p>
 * The default hash function is SHA1 (1.3.14.3.2.26). The only supported mask
 * generation function is MGF1 (1.2.840.113549.1.1.8). The only supported
 * PSource algorithm is <tt>pSpecified</tt> (1.2.840.113549.1.1.9).
 * 
 * @author Thomas Wahrenbruch
 * @author Ralf-Philipp Weinmann
 * @author Martin Döring
 */
public class RSAOAEPParameterSpec implements AlgorithmParameterSpec {

    /**
     * The OID of the default hash function (SHA1)
     */
    public static final String DEFAULT_MD = "1.3.14.3.2.26";

    /**
     * The OID of the default mask generation function (MGF1)
     */
    public static final String DEFAULT_MGF = "1.2.840.113549.1.1.8";

    /**
     * The OID of the default PSource algorithm (<tt>pSpecified</tt>)
     */
    public static final String DEFAULT_PSOURCE = "1.2.840.113549.1.1.9";

    // the OID of the hash function
    private String md;

    /**
     * Construct the default RSA-OAEP parameters. Choose the
     * {@link #DEFAULT_MD default message digest}.
     */
    public RSAOAEPParameterSpec() {
	this(DEFAULT_MD);
    }

    /**
     * Construct new RSA-OAEP parameters from the given OIDs of the hash
     * function, mask generation function, and PSource algorithm.
     * 
     * @param md
     *                the OID of the hash function
     */
    public RSAOAEPParameterSpec(String md) {
	this.md = md;
    }

    /**
     * @return the OID of the hash function
     */
    public String getMD() {
	return md;
    }

    /**
     * Compare the parameters with another object
     * 
     * @param other
     *                the other object
     * @return the result of the comparison
     */
    public boolean equals(Object other) {
	if ((other == null) || (!(other instanceof RSAOAEPParameterSpec))) {
	    return false;
	}

	return md.equals(((RSAOAEPParameterSpec) other).md);
    }

    /**
     * @return the hash code of the parameters
     */
    public int hashCode() {
	return md.hashCode() + DEFAULT_MGF.hashCode()
		+ DEFAULT_PSOURCE.hashCode();
    }

    /**
     * @return a human readable form of the parameters
     */
    public String toString() {
	String result = "RSA OAEP parameters:\n";
	result += "MD OID     : " + md + "\n";
	result += "MGF OID    : " + DEFAULT_MGF + "\n";
	result += "PSource OID: " + DEFAULT_PSOURCE + "\n";
	return result;
    }

}
