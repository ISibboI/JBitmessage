package de.flexiprovider.pqc.tss;

import java.util.Vector;

import de.flexiprovider.common.math.polynomials.GFP64Polynomial;

/**
 * This class implements the hash function used for the signature. It is
 * described in the paper on page 7 (2.3 A hash function family)
 * 
 */
public class TSSHashFunction {

	private int m;
	private Vector a;

	/**
	 * Constructor
	 * 
	 * @param a
	 *            a vector of {@link GFP64Polynomial}
	 */
	public TSSHashFunction(Vector a) {
		this.a = a;
		m = a.size();
	}

	/**
	 * this method calculates the hash of a given vector of
	 * {@link GFP64Polynomial}
	 * 
	 * @param vec
	 *            a vector of {@link GFP64Polynomial}
	 * @return a {@link GFP64Polynomial}
	 */
	public TSSPolynomial calculatHash(Vector vec) {
		Vector intermediateResult = new Vector();
		for (int i = m; i > 0; i--) {
			intermediateResult.addElement(((TSSPolynomial) a.elementAt(i - 1))
					.multiply((TSSPolynomial) vec.elementAt(i - 1)));
		}

		return elementSum(intermediateResult);
	}

	private TSSPolynomial elementSum(Vector v) {
		int size = v.size();
		TSSPolynomial result = (TSSPolynomial) v.elementAt(size - 1);

		for (int j = size - 1; j > 0; j--) {
			result.addToThis((TSSPolynomial) v.elementAt(j - 1));
		}

		return result;
	}
}
