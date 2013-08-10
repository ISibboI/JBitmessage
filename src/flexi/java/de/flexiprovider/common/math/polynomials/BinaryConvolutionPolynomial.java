package de.flexiprovider.common.math.polynomials;

import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.common.util.IntUtils;

/**
 * This class represents binary polynomials in the ring <tt>Z(X)/(X^N-1)</tt>.
 * The coefficients of the polynomials are stored as compressed int arrays (32
 * coefficients per int).
 * 
 * @author Martin Döring
 */
public class BinaryConvolutionPolynomial implements ConvolutionPolynomial {

    /**
     * The degree of the reduction polynomial
     */
    int N;

    /**
     * The degree of this polynomial
     */
    int degree;

    /**
     * The coefficient array
     */
    int[] coefficients;

    /*
     * Constructors
     */

    /**
     * Create a binary polynomial out of the given coefficient array
     * 
     * @param N
     *                the degree of the reduction polynomial
     * @param coefficients
     *                the coefficient array
     * @throws IllegalArgumentException
     *                 if the degree of the given coefficient array is
     *                 <tt>&gt;= N</tt>.
     */
    public BinaryConvolutionPolynomial(final int N, final int[] coefficients)
	    throws IllegalArgumentException {
	this.N = N;
	degree = computeDegree(coefficients);
	if (degree >= N) {
	    throw new IllegalArgumentException("Degree is >= N.");
	}
	this.coefficients = IntUtils.clone(coefficients);
    }

    /**
     * Create a binary polynomial of degree less than <tt>N</tt>.
     * 
     * @param N
     *                the degree of the reduction polynomial
     * @param d
     *                the number of non-zero coefficients
     * @param sr
     *                source of randomness to create the polynomial
     */
    public BinaryConvolutionPolynomial(final int N, final int d, SecureRandom sr) {
	if (N < 0) {
	    this.N = 1;
	} else {
	    this.N = N;
	}

	int thisD = d;
	if (thisD < 0) {
	    thisD = 0;
	}
	if (thisD > N + 1) {
	    thisD = N + 1;
	}

	if (sr == null) {
	    sr = Registry.getSecureRandom();
	}

	int[] index = new int[N];
	for (int i = 0; i < N; i++) {
	    index[i] = i;
	}

	coefficients = new int[(N + 31) >>> 5];
	int k = N;
	for (int i = 0; i < d; i++) {
	    int n = sr.nextInt(k);
	    setCoefficient(index[n]);
	    k--;
	    index[n] = index[k];
	}

	computeDegree();
    }

    /**
     * Copy constructor.
     * 
     * @param other
     *                another <tt>BinaryPolynomial</tt>
     */
    public BinaryConvolutionPolynomial(final BinaryConvolutionPolynomial other) {
	N = other.N;
	this.degree = other.degree;
	coefficients = IntUtils.clone(other.coefficients);
    }

    /*
     * Public methods
     */

    /**
     * Set the coefficient with the given index. If the index is out of bounds,
     * do nothing.
     * 
     * @param index
     *                the index
     */
    public void setCoefficient(final int index) {
	if (index < 0 || index >= N) {
	    return;
	}

	coefficients[index >>> 5] |= 1 << (index & 0x1f);
    }

    /**
     * Test whether the coefficient with the given index is 1. If the index if
     * out of bounds, return <tt>false</tt>.
     * 
     * @param index
     *                the index of the coefficient to test
     * @return <tt>true</tt> if the coefficient with the given index is 1,
     *         <tt>false</tt> otherwise or if the index is out of bounds
     */
    public boolean testCoefficient(final int index) {
	if (index < 0 || index > degree) {
	    return false;
	}
	return (coefficients[index >>> 5] & (1 << (index & 0x1f))) != 0;
    }

    /**
     * Compute an array of bit pattern locations given a windows size according
     * to Algorithm 2 of M.-K. Lee, J. W. Kim, J. E. Song, and K. Park, "Sliding
     * Window Method for NTRU", LNCS 4521.
     * 
     * @param w
     *                the window size
     * @return an array [b_0, ... b_{w-1}] of bit pattern locations
     */
    int[][] getPatternLocations(int w) {
	int numCoeffs = numCoeffs();
	int[][] locations = new int[w][(numCoeffs >> 1) + 2];
	locations[0] = new int[numCoeffs + 1];
	int currentPos = degree;

	while (currentPos > 0) {
	    boolean patternFound = false;

	    if (testCoefficient(currentPos)) {

		for (int j = 1; j < w; j++) {
		    if (testCoefficient(currentPos - j)) {
			locations[j][locations[j][0]++ + 1] = currentPos;
			currentPos -= j + 1;
			patternFound = true;
			break;
		    }
		}

		if (!patternFound) {
		    locations[0][locations[0][0]++ + 1] = currentPos;
		    currentPos -= w;
		}

	    } else {
		currentPos--;
	    }
	}

	if (currentPos == 0 && testCoefficient(0)) {
	    locations[0][locations[0][0]++ + 1] = 0;
	}

	return locations;
    }

    /**
     * Compare this binary polynomial with the given object.
     * 
     * @param other
     *                the other object
     * @return the result of the comparison
     */
    public boolean equals(Object other) {
	if (other == null || !(other instanceof BinaryConvolutionPolynomial)) {
	    return false;
	}

	BinaryConvolutionPolynomial otherPol = (BinaryConvolutionPolynomial) other;

	if (N == otherPol.N && degree == otherPol.degree
		&& IntUtils.equals(coefficients, otherPol.coefficients)) {
	    return true;
	}

	return false;
    }

    /**
     * @return the hash code of this polynomial
     */
    public int hashCode() {
	return N + degree + coefficients.hashCode();
    }

    /**
     * @return a human readable form of this polynomial
     */
    public String toString() {
	String result = "BinaryConvolutionPolynomial (degree " + degree
		+ "):\n";
	result += "x^" + degree;
	for (int i = degree - 1; i >= 0; i--) {
	    if (testCoefficient(i)) {
		result += " + x^" + i;
	    }
	}

	// alternative representation (bit string)
	result += "\n";
	for (int i = degree; i >= 0; i--) {
	    result += testCoefficient(i) ? "1" : "0";
	}
	return result;
    }

    /**
     * Compute the degree of this binary polynomial.
     */
    private void computeDegree() {
	for (degree = (coefficients.length << 5) - 1; !testCoefficient(degree); degree--)
	    ;
    }

    /**
     * Compute the degree of the binary polynomial given as its coefficient
     * array.
     * 
     * @return the degree of the binary polynomial
     */
    private int computeDegree(int[] coefficients) {
	int degree;
	for (degree = (coefficients.length << 5) - 1; !testCoefficient(degree); degree--)
	    ;
	return degree;
    }

    /**
     * Compute the number of 1 coefficients of this binary polynomial.
     * 
     * @return the number of 1 coefficients
     */
    int numCoeffs() {
	int numCoeffs = 0;
	for (int i = degree; i >= 0; i--) {
	    if (testCoefficient(i)) {
		numCoeffs++;
	    }
	}
	return numCoeffs;
    }

}
