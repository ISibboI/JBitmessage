package de.flexiprovider.core.dsa;

import de.flexiprovider.api.exceptions.InvalidParameterException;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;

/**
 * This class specifies parameters used for initializing the
 * {@link DSAParameterGenerator}. The parameters consist of the bit size of the
 * prime <tt>p</tt>.
 * 
 * @author Martin Döring
 */
public class DSAParamGenParameterSpec implements AlgorithmParameterSpec {

    /**
     * The default bit length of the prime <tt>p</tt> (1024 bits).
     */
    public static final int DEFAULT_L = 1024;

    /**
     * The default bit length of the prime <tt>q</tt>.
     */
    public static final int DEFAULT_N = 160;

    // the bit length of the prime p
    private int L;

    // the bit length of the prime q
    private int N;

    /**
     * Constructor. Set the default parameters.
     */
    public DSAParamGenParameterSpec() {
	this(DEFAULT_L, DEFAULT_N);
    }

    /**
     * Constructor.
     * 
     * @param keySize
     *                the bit length of the prime <tt>p</tt> (1024 or 2048)
     * @throws InvalidParameterException
     *                 if the key size is invalid.
     */
    public DSAParamGenParameterSpec(int keySize)
	    throws InvalidParameterException {
	if (keySize == DEFAULT_L) {
	    L = DEFAULT_L;
	    N = DEFAULT_N;
	} else if (keySize == 2048) {
	    L = keySize;
	    N = 224;
	} else if (keySize == 3072) {
	    L = keySize;
	    N = 256;
	} else {
	    throw new InvalidParameterException(
		    "key size must either 1024 or 2048");
	}
    }

    /**
     * Constructor.
     * 
     * @param L
     *                the bit length of the prime <tt>p</tt>
     * @param N
     *                the bit length of the prime <tt>q</tt>
     * @throws InvalidParameterException
     *                 if <tt>L &lt; 1</tt> or <tt>N &lt; 1</tt>.
     */
    public DSAParamGenParameterSpec(int L, int N)
	    throws InvalidParameterException {
	if (L < 1) {
	    throw new InvalidParameterException("L must be positive");
	}
	this.L = L;

	if (N < 1) {
	    throw new InvalidParameterException("N must be positive");
	}
	this.N = N;
    }

    /**
     * @return the bit length of the prime <tt>p</tt>
     */
    public int getL() {
	return L;
    }

    /**
     * @return the bit length of the prime <tt>q</tt>
     */
    public int getN() {
	return N;
    }

}
