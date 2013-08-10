package de.flexiprovider.common.math.polynomials;

import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.common.math.IntegerFunctions;

/**
 * This class represents product form polynomials in <tt>Z(X)/(X^N-1)</tt>,
 * i.e. polynomials of the form <tt>f1*f2+f3</tt>, where <tt>f1</tt>,
 * <tt>f2</tt>, and <tt>f3</tt> are sparse binary polynomials.
 * <p>
 * The fields have package visibility so that they can be accessed by
 * {@link de.flexiprovider.common.math.polynomials.ModQConvolutionPolynomial}.
 * 
 * @author Martin Döring
 * @see de.flexiprovider.common.math.polynomials.SparseBinaryConvolutionPolynomial
 */
public class ProductFormConvolutionPolynomial implements ConvolutionPolynomial {

    /**
     * The degree of the reduction polynomial
     */
    int N;

    /**
     * The three sparse binary polynomials
     */
    SparseBinaryConvolutionPolynomial f1, f2, f3;

    /*
     * Constructors
     */

    /**
     * Construct a random product form polynomial.
     * 
     * @param N
     *                the degree of the reduction polynomial
     * @param d1
     *                the number of non-zero coefficients of the first sparse
     *                binary polynomial
     * @param d2
     *                the number of non-zero coefficients of the second sparse
     *                binary polynomial
     * @param d3
     *                the number of non-zero coefficients of the third sparse
     *                binary polynomial
     * @param sr
     *                the source of randomness used for creating the sparse
     *                binary polynomial
     */
    public ProductFormConvolutionPolynomial(int N, int d1, int d2, int d3,
	    SecureRandom sr) {
	if (N < 0) {
	    this.N = 0;
	} else {
	    this.N = N;
	}

	f1 = new SparseBinaryConvolutionPolynomial(N, d1, sr);
	f2 = new SparseBinaryConvolutionPolynomial(N, d2, sr);
	f3 = new SparseBinaryConvolutionPolynomial(N, d3, sr);
    }

    /**
     * Construct a product form polynomial out of the three given sparse binary
     * polynomials.
     * 
     * @param f1
     *                the first sparse binary polynomial
     * @param f2
     *                the second sparse binary polynomial
     * @param f3
     *                the third sparse binary polynomial
     * @throws ArithmeticException
     *                 if the sparse binary polynomials are not elements of the
     *                 same ring
     */
    public ProductFormConvolutionPolynomial(
	    SparseBinaryConvolutionPolynomial f1,
	    SparseBinaryConvolutionPolynomial f2,
	    SparseBinaryConvolutionPolynomial f3) throws ArithmeticException {

	if (f1.N != f2.N || f1.N != f3.N) {
	    throw new ArithmeticException(
		    "Binary polynomials are not elements of the same ring.");
	}

	this.N = f1.N;
	this.f1 = f1;
	this.f2 = f2;
	this.f3 = f3;
    }

    /**
     * Copy constructor.
     * 
     * @param other
     *                another <tt>ModQPolynomialProductForm</tt>
     */
    public ProductFormConvolutionPolynomial(
	    ProductFormConvolutionPolynomial other) {
	N = other.N;
	f1 = new SparseBinaryConvolutionPolynomial(other.f1);
	f2 = new SparseBinaryConvolutionPolynomial(other.f2);
	f3 = new SparseBinaryConvolutionPolynomial(other.f3);
    }

    /**
     * Construct a product form polynomial given three encoded sparse binary
     * polynomials.
     * 
     * @param N
     *                the degree of the reduction polynomial
     * @param d1
     *                the number of non-zero coefficients of the first sparse
     *                binary polynomial
     * @param d2
     *                the number of non-zero coefficients of the second sparse
     *                binary polynomial
     * @param d3
     *                the number of non-zero coefficients of the third sparse
     *                binary polynomial
     * @param enc1
     *                the first encoded sparse binary polynomial
     * @param enc2
     *                the second encoded sparse binary polynomial
     * @param enc3
     *                the third encoded sparse binary polynomial
     * @throws IllegalArgumentException
     *                 if the encoded polynomials have wrong length.
     */
    private ProductFormConvolutionPolynomial(int N, int d1, int d2, int d3,
	    byte[] enc1, byte[] enc2, byte[] enc3)
	    throws IllegalArgumentException {
	this.N = N;
	f1 = SparseBinaryConvolutionPolynomial.OS2REP(N, d1, enc1);
	f2 = SparseBinaryConvolutionPolynomial.OS2REP(N, d2, enc2);
	f3 = SparseBinaryConvolutionPolynomial.OS2REP(N, d3, enc3);
    }

    /*
     * Public methods
     */

    /**
     * Encode this polynomial as a byte array.
     * 
     * @param N
     *                the degree of the reduction polynomial
     * @return the encoded polynomial
     * @throws ArithmeticException
     *                 if this polynomial is not a binary element of
     *                 <tt>Z(X)/(X^N-1)</tt>.
     */
    public byte[] RE2OSP(int N) throws ArithmeticException {
	if (this.N != N) {
	    throw new ArithmeticException("Not an element of Z(X)/(X^N-1).");
	}
	byte[] enc1 = f1.RE2OSP();
	byte[] enc2 = f2.RE2OSP();
	byte[] enc3 = f3.RE2OSP();
	byte[] result = new byte[enc1.length + enc2.length + enc3.length];
	System.arraycopy(enc1, 0, result, 0, enc1.length);
	System.arraycopy(enc2, 0, result, enc1.length, enc2.length);
	System.arraycopy(enc3, 0, result, enc1.length + enc2.length,
		enc3.length);
	return result;
    }

    /**
     * Decode a byte array into a product form polynomial.
     * 
     * @param N -
     *                the degree of the reduction polynomial
     * @param q -
     *                the modulus
     * @param d1 -
     *                the number of non-zero coefficients of the first sparse
     *                binary polynomial
     * @param d2 -
     *                the number of non-zero coefficients of the second sparse
     *                binary polynomial
     * @param d3 -
     *                the number of non-zero coefficients of the third sparse
     *                binary polynomial
     * @param encoded -
     *                the encoded polynomial
     * @return the decoded polynomial
     * @throws IllegalArgumentException
     *                 if the encoded polynomial has wrong length.
     */
    public static ProductFormConvolutionPolynomial OS2REP(int N, int q, int d1,
	    int d2, int d3, byte[] encoded) throws IllegalArgumentException {
	int oLen = IntegerFunctions.ceilLog256(N - 1);
	if (encoded.length != oLen * (d1 + d2 + d3)) {
	    throw new IllegalArgumentException(
		    "Encoded product form polynomial has wrong length.");
	}

	if (q == 0) {
	    q = 2;
	}
	if (q < 0) {
	    q = -q;
	}

	byte[] enc1 = new byte[oLen * d1];
	byte[] enc2 = new byte[oLen * d2];
	byte[] enc3 = new byte[oLen * d3];
	System.arraycopy(encoded, 0, enc1, 0, enc1.length);
	System.arraycopy(encoded, enc1.length, enc2, 0, enc2.length);
	System.arraycopy(encoded, enc1.length + enc2.length, enc3, 0,
		enc3.length);

	return new ProductFormConvolutionPolynomial(N, d1, d2, d3, enc1, enc2,
		enc3);
    }

    /**
     * Compare this polynomial with the given object.
     * 
     * @param other
     *                the other object
     * @return the result of the comparison
     */
    public boolean equals(Object other) {
	if (other == null
		|| !(other instanceof ProductFormConvolutionPolynomial)) {
	    return false;
	}

	ProductFormConvolutionPolynomial otherPol = (ProductFormConvolutionPolynomial) other;

	if (N == otherPol.N && f1.equals(otherPol.f1) && f2.equals(otherPol.f2)
		&& f3.equals(otherPol.f3)) {
	    return true;
	}

	return false;
    }

    /**
     * @return the hash code of this polynomial
     */
    public int hashCode() {
	return N + f1.hashCode() + f2.hashCode() + f3.hashCode();
    }

    /**
     * @return a human readable form of this polynomial
     */
    public String toString() {
	String result = "ModQPolynomialProductForm (degree " + N + "):\n";
	result += "Polynomial f1: " + f1 + "\n";
	result += "Polynomial f2: " + f2 + "\n";
	result += "Polynomial f3: " + f3;
	return result;
    }

}
