package de.flexiprovider.nf.iq.iqrdsa;

import de.flexiprovider.api.parameters.AlgorithmParameterSpec;

/**
 * This class specifies parameters used for initializing the
 * {@link IQRDSAParameterGenerator}. The parameters consist of the bit length
 * of the discriminant.
 * 
 * @author Martin Döring
 */
public class IQRDSAParamGenParameterSpec implements AlgorithmParameterSpec {

    /**
     * The default bit length of the discriminant (768)
     */
    public static final int DEFAULT_SIZE = 768;

    /**
     * The maximal bit length of the discriminant (16384)
     */
    public static final int MAX_SIZE = 16384;

    private int size;

    /**
     * Construct the default IQRDSA parameter generation parameters. Choose the
     * bit length of the discriminant as {@link #DEFAULT_SIZE}.
     */
    public IQRDSAParamGenParameterSpec() {
	this(DEFAULT_SIZE);
    }

    /**
     * Construct new IQRDSA parameter generation parameters from the desired bit
     * length of the discriminant.
     * <p>
     * If the bit length of the discriminant is &lt; 2, the
     * {@link #DEFAULT_SIZE} is used as bit length. If the bit length is &gt;
     * {@link #MAX_SIZE}, {@link #MAX_SIZE} is used as bit length.
     * 
     * @param size
     *                the bit length of the discriminant (&gt;= 2, &lt;=
     *                {@link #MAX_SIZE})
     */
    public IQRDSAParamGenParameterSpec(int size) {
	if (size < 2) {
	    this.size = DEFAULT_SIZE;
	} else if (size > MAX_SIZE) {
	    this.size = MAX_SIZE;
	} else {
	    this.size = size;
	}
    }

    /**
     * @return the bit length of the discriminant
     */
    public int getSize() {
	return size;
    }

}
