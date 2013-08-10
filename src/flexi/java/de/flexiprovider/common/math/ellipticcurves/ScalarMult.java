package de.flexiprovider.common.math.ellipticcurves;

import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.math.finitefields.GF2nElement;
import de.flexiprovider.common.math.finitefields.GF2nField;
import de.flexiprovider.common.math.finitefields.GF2nONBElement;
import de.flexiprovider.common.math.finitefields.GF2nONBField;
import de.flexiprovider.common.math.finitefields.GF2nPolynomialElement;
import de.flexiprovider.common.math.finitefields.GF2nPolynomialField;
import de.flexiprovider.common.math.finitefields.GFPElement;

public final class ScalarMult {

    /**
     * Default constructor (private).
     */
    private ScalarMult() {
	// empty
    }

    // ////////////////////////////////////////////////////////////////////
    // multiplications
    // ////////////////////////////////////////////////////////////////////

    /**
     * Multiplies this point with the scalar <tt>b</tt>. Naf-recoding (<tt>w = 4</tt>)
     * and CMO-Precomputation will be used.
     * 
     * @param b
     *                <tt>FlexiBigInt</tt>
     * 
     * @param p
     *                base point
     * 
     * @return <tt>b*p</tt>
     */
    public static Point multiply(FlexiBigInt b, Point p) {
	int w = 4;
	int[] N = determineNaf(b, w);
	Point[] P = precomputationCMO(p, w + 1, 0);
	Point R = eval_SquareMultiply(N, P);
	return R;
    }

    public static Point multiply2(FlexiBigInt b, Point p) {
	int w = 4;
	int[] N = determineNaf(b, w);
	Point[] P = precomputation(p, w + 1, 0);
	Point R = eval_SquareMultiply(N, P);
	return R;
    }

    public static Point multiply3(FlexiBigInt b, Point p) {
	int w = 4;
	int[] N = determineSW(b, w);
	Point[] P = precomputationCMO(p, w + 1, 0);
	Point R = eval_SquareMultiply(N, P);
	return R;
    }

    public static Point multiply4(FlexiBigInt b, PointGFP p) {
	int w = 3;
	int[] N = determineNaf(b, w);
	Point[] P = precomputationDOS(p, 1 << (w - 1));
	Point R = eval_SquareMultiply(N, P);
	return R;
    }

    /**
     * Returns the result of the simultaneous scalarmultiplication
     * <tt>b<sub>0</sub>*P<sub>0</sub> + b<sub>1</sub>*P<sub>1</sub> + 
     *  ... + b<sub>n-1</sub>*P<sub>n-1</sub></tt>.<br>
     * This method uses Naf-recoding (<tt>w = 4</tt>), CMO-Precomputation
     * and the interleaving method.
     * 
     * @param p
     *                Array of base points
     * @param b
     *                Array of <tt>FlexiBigInt</tt>
     * @return <tt>b<sub>0</sub>*P<sub>0</sub> + b<sub>1</sub>*P<sub>1</sub> + 
     *  ... + b<sub>n-1</sub>*P<sub>n-1</sub></tt>
     */
    public static Point multiply(FlexiBigInt[] b, Point[] p) {
	int w = 5;
	int[] W = new int[b.length];
	for (int i = 0; i < W.length; i++) {
	    W[i] = w;
	}
	int[][] N = determineSimultaneousNaf(b, W);
	Point[][] P = new Point[b.length][1 << (w - 1)];
	for (int i = 0; i < b.length; i++) {
	    P[i] = precomputationCMO(p[i], w + 1, 0);
	}
	Point R = eval_interleaving(N, P);
	return R;
    }

    public static Point multiply2(FlexiBigInt[] b, Point[] p) {
	int w = 4;
	int[] W = new int[b.length];
	for (int i = 0; i < W.length; i++) {
	    W[i] = w;
	}
	int[][] N = determineSimultaneousNaf(b, W);
	Point[][] P = new Point[b.length][1 << (w - 1)];
	for (int i = 0; i < b.length; i++) {
	    P[i] = precomputation(p[i], w + 1, 0);
	}
	Point R = eval_interleaving(N, P);
	return R;
    }

    public static Point multiply3(FlexiBigInt[] b, Point[] p) {
	int w = 4;
	int bitlength = 0;
	for (int i = 0; i < b.length; i++) {
	    bitlength = (bitlength < b[i].bitLength()) ? b[i].bitLength()
		    : bitlength;
	}
	int[][] N = new int[b.length][bitlength + 1];
	for (int i = 0; i < b.length; i++) {
	    N[i] = determineSW(b[i], w);
	}
	Point[][] P = new Point[b.length][1 << (w - 1)];
	for (int i = 0; i < b.length; i++) {
	    P[i] = precomputationCMO(p[i], w + 1, 0);
	}
	Point R = eval_interleaving(N, P);
	return R;
    }

    public static Point multiply4(FlexiBigInt[] b, PointGFP[] p) {
	int w = 3;
	int[] W = new int[b.length];
	for (int i = 0; i < W.length; i++) {
	    W[i] = w;
	}
	int[][] N = determineSimultaneousNaf(b, W);
	Point[][] P = new Point[b.length][1 << (w - 1)];
	for (int i = 0; i < b.length; i++) {
	    P[i] = precomputationDOS(p[i], 1 << (w - 1));
	}
	Point R = eval_interleaving(N, P);
	return R;
    }

    // ////////////////////////////////////////////////////////////////////
    // Precomputation
    // ////////////////////////////////////////////////////////////////////

    /**
     * This method computes all positive powers which are smaller than 2<sup>w</sup>.
     * This precomputation is used by representations which have positive,
     * arbitrary digits. An Example is Fixed Size Sliding Window.
     * 
     * @param p
     *                base point
     * @param w
     *                upper bound/ window width
     * @return <tt>i*p</tt> for <tt>i = 0, 1, 2,..., 2<sup>w</sup> - 1</tt>;<br>
     *         <tt>P[i] = (i + 1)*p</tt>
     */
    public static Point[] pre_allpowers(Point p, int w) {
	final int l = (1 << w) - 1;
	Point[] P = new Point[l];
	P[0] = (Point) p.clone();
	int t = 1 << (w - 1);
	for (int i = 1; i < t; i++) {
	    int j = i << 1;
	    P[j - 1] = P[i - 1].multiplyBy2();
	    P[j] = P[j - 1].add(p);
	}
	return P;
    }

    /**
     * This method computes all positive odd powers which are smaller than 2<sup>w</sup>.
     * It is useful for representations which use odd digits. Examples are Naf,
     * Sliding Window or Mof.
     * 
     * @param p
     *                base point
     * @param w
     *                upper bound/ window width
     * @return <tt>i*p</tt> for <tt>i = 0, 1, 3,..., 2<sup>w</sup> - 1</tt>;<br>
     *         <tt>P[i] = (2i + 1)*p</tt>
     */
    public static Point[] pre_oddpowers(Point p, int w) {
	final int l = (1 << w) - 1;
	Point[] P = new Point[l];
	P[0] = (Point) p.clone();
	Point tmp = p.multiplyBy2();

	for (int i = 1; i < l; i++) {
	    P[i] = P[i - 1].add(tmp);
	}
	return P;
    }

    /**
     * This method computes all positive odd powers of all points given in array
     * Q. The corresponding window widthes must be provided by an array W. For
     * every Point P[i], all odd powers are computed which are smaller than 2<sup>W[i]</sup>.
     * <br>
     * Note that (W.length = Q.length) is required.<br>
     * This method returns a matrix Pre[][]. A certain precomputation of P[i] is
     * found in Pre[i].
     * 
     * @param Q
     *                base point array. All points must be on the same elliptic
     *                curve.
     * @param W
     *                upper bound array. W[i] is the upper bound for P[i].
     * @return Point matrix with e.length lines and 2<sup>w</sup> columns.<br>
     *         The odd powers of <tt>Q[i]</tt> are stored in line i;
     */
    public static Point[][] pre_oddpowers(Point[] Q, int[] W) {
	int w = 0;
	for (int i = 0; i < W.length; i++) {
	    w = (w < W[i]) ? W[i] : w;
	}

	Point[][] P;
	int l1 = Q.length;
	int l = 1 << (w - 1);

	P = createPointMatrix(Q[0], Q[0], l1, l);
	for (int j = 0; j < l1; j++) {
	    P[j][0] = Q[j];
	    Point q2 = Q[j].multiplyBy2();
	    for (int i = 1; i < l; i++) {
		P[j][i] = P[j][i - 1].add(q2);
	    }
	}
	return P;
    }

    public static Point[] precomputation(Point p, int w, int k) {
	int length = 1;
	if (w != 0 && k == 0) {
	    w = w - 1;
	    length = 1 << (w - 1); // length == #precomputed points + 1
	}
	if (w == 0 && k != 0) {
	    length = k; // length == #precomputed points + 1
	    int bits = (Integer.toBinaryString(k - 1)).length();
	    // numbers of bits of k-1
	    w = bits + 1;
	}
	Point[] P = new Point[length];
	P[0] = (Point) p.clone();

	if (w <= 1) {
	    return P;
	}

	Point tmp = p.multiplyBy2Affine();

	for (int i = 1; i < length; i++) {
	    P[i] = P[i - 1].addAffine(tmp);
	}
	return P;
    }

    public static Point[] precomputationCMO(Point p, int w, int k) {
	if (p instanceof PointGFP) {
	    return precomputationCMO((PointGFP) p, w, k);
	} else if (p instanceof PointGF2n) {
	    if (w != 0) {
		return precomputationCMO((PointGF2n) p, w);
	    }
	    throw new RuntimeException(
		    "PrecomputationCMO on EllipticCurveGF2n "
			    + "with k != 0 is not supported.");
	} else {
	    throw new RuntimeException(
		    "Point must be an instance of PointGFP / PointGF2n"
			    + " and windowsize must be at least 2.");
	}
    }

    /**
     * If k = 0 and w != 0 this method precomputes all odd points 3P, 5P,
     * 7P,..., (2<sup>w-1</sup> -1)P in affine coordinates, whereas P = point.
     * <p>
     * If k != 0 and w = 0 this method precomputes all odd points 3P, 5P,
     * 7P,..., (2k-1)P in affine coordinates, whereas P = point.
     * <p>
     * This method computes these points with the algorithm thas was proposed in
     * <i> Cohen, H., Miyaji, A., and Ono, T. Efficient Elliptic Curve
     * Exponentiation Using Mixed Coordinates. 1998</i>
     * <p>
     * The elements of the returned array are as followed: <br>
     * <br>
     * <table border="0">
     * <tr>
     * <td><b>w != 0, k = 0</b></td>
     * <td>&#160;&#160;</td>
     * <td><b>w = 0, k != 0</b></td>
     * <td>&#160;&#160;</td>
     * <td><b>w != 0, k != 0</b></td>
     * </tr>
     * <tr></tr>
     * <tr>
     * <td>array[0] = P</td>
     * <td>&#160;&#160;</td>
     * <td>array[0] = P</td>
     * <td>&#160;&#160;</td>
     * <td>array[0] = P</td>
     * </tr>
     * <tr>
     * <td>array[1] = 3P</td>
     * <td>&#160;&#160;</td>
     * <td>array[1] = 3P</td>
     * <td>&#160;&#160;</td>
     * <td></td>
     * </tr>
     * <tr>
     * <td>array[2] = 5P</td>
     * <td>&#160;&#160;</td>
     * <td>array[2] = 5P</td>
     * <td>&#160;&#160;</td>
     * <td></td>
     * </tr>
     * <tr>
     * <td>...</td>
     * <td>&#160;&#160;</td>
     * <td>...</td>
     * <td>&#160;&#160;</td>
     * <td></td>
     * </tr>
     * <tr>
     * <td>array[(2<sup>w-2</sup>)-1] = (2<sup>w-1</sup> -1)P</td>
     * <td>&#160;&#160;</td>
     * <td>array[k-1] = (2k-1)P</td>
     * <td>&#160;&#160;</td>
     * <td></td>
     * </tr>
     * </table>
     * 
     * @param p
     *                the point of the scalar multiplication
     * @param w
     *                window size
     * @param k
     *                the number of points to compute
     * 
     * @return Returns an array with the precomputed points in affine
     *         coordinates
     */
    public static Point[] precomputationCMO(PointGFP p, int w, int k) {
	int length, denoms;
	Point[] P;
	if (w > 2 && k == 0) {
	    w = w - 1;
	    length = 1 << (w - 1); // length == #precomputed points + 1
	    denoms = 1 << (w - 2); // denoms == #lambdas denominators
	} else if (w == 0 && k > 1) {
	    length = k; // length == #precomputed points + 1
	    int bits = (Integer.toBinaryString(k - 1)).length();
	    // numbers of bits of k-1
	    w = bits + 1;
	    denoms = 1 << (bits - 1); // denoms == #lambdas denominators
	} else {
	    P = new Point[1];
	    P[0] = (PointGFP) p.clone();
	    return P;
	}

	P = new Point[length];
	P[0] = (PointGFP) p.clone();

	PointGFP doubleP = (PointGFP) p.multiplyBy2Affine();
	doubleP = (PointGFP) doubleP.getAffin(); // 2P

	// arrays for lambdas denominators and their inverses
	FlexiBigInt[] NennerLambda = new FlexiBigInt[denoms];
	FlexiBigInt[] NennerLambdaInvers = new FlexiBigInt[denoms];
	FlexiBigInt invers = null;

	FlexiBigInt mP = p.getE().getQ();

	for (int i = 1; i < w; i++) {
	    final int begin = 1 << i - 1; // startposition
	    final int end = (1 << i) - 1; // endposition
	    boolean notLastStep = (i + 1) != w;
	    // in last step you can save some computations
	    int start = 0;

	    // compute lambdas denominators
	    if (notLastStep) {
		// example NennerLambda = |NL(5P) | NL(7P) | NL(8P)| with
		// w>3
		for (int j = begin; j <= end; j++) {
		    NennerLambda[start] = doubleP.getX().toFlexiBigInt()
			    .subtract(
				    ((PointGFP) P[start]).getX()
					    .toFlexiBigInt());
		    start++;
		}
		NennerLambda[start] = doubleP.getY().toFlexiBigInt().add(
			doubleP.getY().toFlexiBigInt()).mod(mP);
		NennerLambdaInvers[0] = NennerLambda[0].add(FlexiBigInt.ZERO);

		// example NennerLambdaInvers =
		// |NL(5P) | NL(5P)*NL(7P) | NL(5P)*NL(7P)*NL(8P)| with w>3
		for (int m = 1; m <= begin; m++) {
		    NennerLambdaInvers[m] = (NennerLambdaInvers[m - 1]
			    .multiply(NennerLambda[m])).mod(mP);
		}

		invers = NennerLambdaInvers[begin].modInverse(mP);

		// example NennerLambdaInvers = |NL(5P)^-1 | NL(7P)^-1 |
		// NL(8P)^-1| with w>3
		for (int m = begin; m >= 1; m--) {
		    NennerLambdaInvers[m] = (NennerLambdaInvers[m - 1]
			    .multiply(invers)).mod(mP);
		    invers = (invers.multiply(NennerLambda[m])).mod(mP);
		}
		NennerLambdaInvers[0] = invers;
	    } else {
		// example NennerLambda = |NL(5P) | NL(7P) | with w==3
		for (int j = begin; j <= end; j++) {
		    NennerLambda[start] = doubleP.getX().toFlexiBigInt()
			    .subtract(
				    ((PointGFP) P[start]).getX()
					    .toFlexiBigInt());
		    start++;
		}
		NennerLambdaInvers[0] = NennerLambda[0].add(FlexiBigInt.ZERO);

		// example NennerLambdaInvers = |NL(5P) | NL(5P)*NL(7P) |
		// with w==3
		for (int m = 1; m < begin; m++) {
		    NennerLambdaInvers[m] = (NennerLambdaInvers[m - 1]
			    .multiply(NennerLambda[m])).mod(mP);
		}

		invers = NennerLambdaInvers[begin - 1].modInverse(mP);

		// example NennerLambdaInvers = |NL(5P)^-1 | NL(7P)^-1 |
		// with w==3
		for (int m = begin - 1; m >= 1; m--) {
		    NennerLambdaInvers[m] = (NennerLambdaInvers[m - 1]
			    .multiply(invers)).mod(mP);
		    invers = (invers.multiply(NennerLambda[m])).mod(mP);
		}
		NennerLambdaInvers[0] = invers;
	    }

	    // compute multiples of point with P[j] = P[start] + doubleP
	    FlexiBigInt lambda = null;
	    FlexiBigInt temp = null;
	    FlexiBigInt x, y, startX, startY;
	    start = 0;
	    for (int j = begin; j <= end; j++) {
		startX = ((PointGFP) P[start]).getX().toFlexiBigInt();
		startY = ((PointGFP) P[start]).getY().toFlexiBigInt();
		lambda = (doubleP.getY().toFlexiBigInt()).subtract(startY);
		lambda = (NennerLambdaInvers[start]).multiply(lambda).mod(mP);

		// new x-coordinate of point P[j]
		temp = lambda.multiply(lambda).mod(mP);
		temp = temp.subtract(startX);
		x = (temp.subtract(doubleP.getX().toFlexiBigInt())).mod(mP);

		// new y-coordinate of Point P[j]
		temp = startX.subtract(x);
		temp = lambda.multiply(temp).mod(mP);
		y = (temp.subtract(startY)).mod(mP);

		GFPElement gfpx = new GFPElement(x, mP);
		GFPElement gfpy = new GFPElement(y, mP);
		P[j] = new PointGFP(gfpx, gfpy, (EllipticCurveGFP) p.getE());
		if (k == j + 1) {
		    return P;
		}
		start++;
	    }

	    // compute new 2*doubleP coordinates
	    if (notLastStep) {
		lambda = doubleP.getX().toFlexiBigInt().multiply(
			doubleP.getX().toFlexiBigInt()).mod(mP);
		lambda = lambda.multiply(
			new FlexiBigInt(java.lang.Integer.toString(3))).mod(mP);
		lambda = lambda.add(doubleP.getE().getA().toFlexiBigInt());
		lambda = lambda.multiply(NennerLambdaInvers[start]).mod(mP);

		// new x-coordinate
		temp = doubleP.getX().toFlexiBigInt().add(
			doubleP.getX().toFlexiBigInt()).mod(mP);
		x = lambda.multiply(lambda).mod(mP).subtract(temp);

		// new y-coordinate
		temp = doubleP.getX().toFlexiBigInt().subtract(x);
		temp = lambda.multiply(temp).mod(mP);
		y = temp.subtract(doubleP.getY().toFlexiBigInt());

		// update doubleP
		// doubleP.mX = new GFPElement(x, mP);
		// doubleP.mY = new GFPElement(y, mP);
		// doubleP.mZ = new GFPElement(FlexiBigInt.ONE, mP);
		doubleP = new PointGFP(new GFPElement(x, mP), new GFPElement(y,
			mP), new GFPElement(FlexiBigInt.ONE, mP),
			(EllipticCurveGFP) doubleP.getE());
	    }
	} // end for
	return P;
    }

    /**
     * If k = 0 and w != 0 this method precomputes all odd points 3P, 5P,
     * 7P,..., (2<sup>w-1</sup> -1)P in affine coordinates, whereas P = point.
     * <p>
     * If k != 0 and w = 0 this method precomputes all odd points 3P, 5P,
     * 7P,..., (2k-1)P in affine coordinates, whereas P = point.
     * <p>
     * This method computes these points with the algorithm thas was proposed in
     * <i> Cohen, H., Miyaji, A., and Ono, T. Efficient Elliptic Curve
     * Exponentiation Using Mixed Coordinates. 1998</i>
     * <p>
     * The elements of the returned array are as followed: <br>
     * <br>
     * <table border="0">
     * <tr>
     * <td><b>w != 0, k = 0</b></td>
     * <td>&#160;&#160;</td>
     * <td><b>w = 0, k != 0</b></td>
     * <td>&#160;&#160;</td>
     * <td><b>w != 0, k != 0</b></td>
     * </tr>
     * <tr></tr>
     * <tr>
     * <td>array[0] = P</td>
     * <td>&#160;&#160;</td>
     * <td>array[0] = P</td>
     * <td>&#160;&#160;</td>
     * <td>array[0] = P</td>
     * </tr>
     * <tr>
     * <td>array[1] = 3P</td>
     * <td>&#160;&#160;</td>
     * <td>array[1] = 3P</td>
     * <td>&#160;&#160;</td>
     * <td></td>
     * </tr>
     * <tr>
     * <td>array[2] = 5P</td>
     * <td>&#160;&#160;</td>
     * <td>array[2] = 5P</td>
     * <td>&#160;&#160;</td>
     * <td></td>
     * </tr>
     * <tr>
     * <td>...</td>
     * <td>&#160;&#160;</td>
     * <td>...</td>
     * <td>&#160;&#160;</td>
     * <td></td>
     * </tr>
     * <tr>
     * <td>array[(2<sup>w-2</sup>)-1] = (2<sup>w-1</sup> -1)P</td>
     * <td>&#160;&#160;</td>
     * <td>array[k-1] = (2k-1)P</td>
     * <td>&#160;&#160;</td>
     * <td></td>
     * </tr>
     * </table>
     * 
     * @param p
     *                the point of the scalar multiplication
     * @param w
     *                window size
     * 
     * @return Returns an array with the precomputed points in affine
     *         coordinates
     */
    public static Point[] precomputationCMO(PointGF2n p, int w) {
	w = w - 1;
	final int length = 1 << (w - 1);
	// length == #precomputed points + 1
	final int denoms = 1 << (w - 2);
	// denoms == #lambdas denominators

	Point[] P = new Point[length];
	P[0] = (PointGF2n) p.clone();
	if (w <= 1) {
	    return P;
	}

	PointGF2n doubleP = (PointGF2n) p.multiplyBy2Affine();
	doubleP = (PointGF2n) doubleP.getAffin(); // 2P

	// arrays for lambdas denominators and their inverses
	GF2nElement[] NennerLambda = new GF2nElement[denoms];
	GF2nElement[] NennerLambdaInvers = new GF2nElement[denoms];
	GF2nElement invers = null;

	for (int i = 1; i < w; i++) {
	    final int begin = 1 << i - 1; // startposition
	    final int end = (1 << i) - 1; // endposition
	    boolean notLastStep = (i + 1) != w;
	    // in last step you can save some computations
	    int start = 0;

	    // compute lambdas denominators
	    if (notLastStep) {
		// example NennerLambda = |NL(5P) | NL(7P) | NL(8P)| with
		// w>3
		for (int j = begin; j <= end; j++) {
		    NennerLambda[start] = (GF2nElement) doubleP.getX().add(
			    ((PointGF2n) P[start]).getX());
		    start++;
		}
		NennerLambda[start] = (GF2nElement) doubleP.getX();
		NennerLambdaInvers[0] = (GF2nElement) NennerLambda[0].clone();

		// example NennerLambdaInvers =
		// |NL(5P) | NL(5P)*NL(7P) | NL(5P)*NL(7P)*NL(8P)| with w>3
		for (int m = 1; m <= begin; m++) {
		    NennerLambdaInvers[m] = (GF2nElement) (NennerLambdaInvers[m - 1]
			    .multiply(NennerLambda[m]));
		}

		invers = (GF2nElement) NennerLambdaInvers[begin].invert();

		// example NennerLambdaInvers = |NL(5P)^-1 | NL(7P)^-1 |
		// NL(8P)^-1| with w>3
		for (int m = begin; m >= 1; m--) {
		    NennerLambdaInvers[m] = (GF2nElement) (NennerLambdaInvers[m - 1]
			    .multiply(invers));
		    invers = (GF2nElement) (invers.multiply(NennerLambda[m]));
		}
		NennerLambdaInvers[0] = invers;
	    } else {
		// example NennerLambda = |NL(5P) | NL(7P) | with w==3
		for (int j = begin; j <= end; j++) {
		    NennerLambda[start] = (GF2nElement) doubleP.getX().add(
			    ((PointGF2n) P[start]).getX());
		    start++;
		}
		NennerLambdaInvers[0] = (GF2nElement) NennerLambda[0].clone();

		// example NennerLambdaInvers = |NL(5P) | NL(5P)*NL(7P) |
		// with w==3
		for (int m = 1; m < begin; m++) {
		    NennerLambdaInvers[m] = (GF2nElement) (NennerLambdaInvers[m - 1]
			    .multiply(NennerLambda[m]));
		}

		invers = (GF2nElement) NennerLambdaInvers[begin - 1].invert();

		// example NennerLambdaInvers = |NL(5P)^-1 | NL(7P)^-1 |
		// with w==3
		for (int m = begin - 1; m >= 1; m--) {
		    NennerLambdaInvers[m] = (GF2nElement) (NennerLambdaInvers[m - 1]
			    .multiply(invers));
		    invers = (GF2nElement) (invers.multiply(NennerLambda[m]));
		}
		NennerLambdaInvers[0] = invers;
	    }

	    // compute multiples of point with P[j] = P[start] + doubleP
	    GF2nElement lambda = null;
	    GF2nElement tmp = null;
	    GF2nElement x, y, startX, startY;
	    start = 0;
	    for (int j = begin; j <= end; j++) {
		startX = (GF2nElement) ((PointGF2n) P[start]).getX();
		startY = (GF2nElement) ((PointGF2n) P[start]).getY();
		lambda = (GF2nElement) (doubleP.getY()).add(startY);
		lambda = (GF2nElement) (NennerLambdaInvers[start])
			.multiply(lambda);

		// new x-coordinate of point P[j]
		tmp = lambda.square();
		tmp = (GF2nElement) lambda.add(tmp);
		tmp = (GF2nElement) tmp.add(doubleP.getX());
		tmp = (GF2nElement) tmp.add(startX);
		x = (GF2nElement) tmp
			.add(((EllipticCurveGF2n) p.getE()).getA());

		// new y-coordinate of Point P[j]
		tmp = (GF2nElement) startX.add(x);
		tmp = (GF2nElement) lambda.multiply(tmp);
		tmp = (GF2nElement) tmp.add(x);
		y = (GF2nElement) tmp.add(startY);

		P[j] = new PointGF2n(x, y, (EllipticCurveGF2n) p.getE());
		start++;
	    }

	    // compute new 2*doubleP coordinates
	    if (notLastStep) {
		lambda = (GF2nElement) doubleP.getY().multiply(
			NennerLambdaInvers[start]);
		lambda = (GF2nElement) lambda.add(doubleP.getX());

		// new x-coordinate
		tmp = lambda.square();
		tmp = (GF2nElement) tmp.add(lambda);
		x = (GF2nElement) tmp
			.add(((EllipticCurveGF2n) p.getE()).getA());

		// new y-coordinate
		GF2nElement element = (GF2nElement) doubleP.getX();
		GF2nField field = element.getField();
		tmp = createGF2nOneElement(field); // temp = 1
		tmp = (GF2nElement) tmp.add(lambda);
		tmp = (GF2nElement) tmp.multiply(x);
		GF2nElement mX = (GF2nElement) doubleP.getX();
		y = (GF2nElement) tmp.add(mX.square());

		// update doubleP
		// doubleP.mX = x;
		// doubleP.mY = y;
		doubleP = new PointGF2n(x, y, (EllipticCurveGF2n) doubleP
			.getE());
	    }
	} // end for
	return P;
    }

    public static PointGFP[] precomputationDOS(PointGFP point, int k) {
	if ((k < 2)) {
	    throw new RuntimeException("window size must be at least 2.");
	}

	FlexiBigInt[] di = new FlexiBigInt[k];
	FlexiBigInt[] ei = new FlexiBigInt[k];
	FlexiBigInt[] fi = new FlexiBigInt[k];
	FlexiBigInt[] li = new FlexiBigInt[k];

	FlexiBigInt T, T1, T2;
	FlexiBigInt A = null;
	FlexiBigInt B = null;
	FlexiBigInt C = null;
	FlexiBigInt D = null;
	FlexiBigInt E = null;
	FlexiBigInt x2, y2, x3, y3, xi, yi;

	// k Punkte werden hier gespeichert von 2P bis (2k-1)P

	PointGFP[] points = new PointGFP[k];

	PointGFP p = (PointGFP) point.clone();
	p = (PointGFP) p.getAffin();

	FlexiBigInt y = p.getY().toFlexiBigInt();
	FlexiBigInt x = p.getX().toFlexiBigInt();
	EllipticCurveGFP el = (EllipticCurveGFP) p.getE();
	FlexiBigInt prime = el.getQ();
	FlexiBigInt a = el.getA().toFlexiBigInt();

	// Step1 Computation of d1,..,dk
	di[0] = (y.multiply(new FlexiBigInt(java.lang.Integer.toString(2))))
		.mod(prime); // d1

	// if(k >= 2) {
	C = di[0].multiply(di[0]).mod(prime);
	A = ((x.multiply(x).mod(prime).multiply(new FlexiBigInt(
		java.lang.Integer.toString(3)))).add(a)).mod(prime);
	B = ((C.multiply(x)).multiply(new FlexiBigInt(java.lang.Integer
		.toString(3)))).mod(prime);
	di[1] = ((A.multiply(A).mod(prime)).subtract(B)).mod(prime); // d2
	// }

	if (k >= 3) {
	    E = di[1].multiply(di[1]).mod(prime);
	    B = (E.multiply(B)).mod(prime);
	    C = C.multiply(C).mod(prime);
	    D = E.multiply(di[1]).mod(prime);
	    A = ((di[1].negate().multiply(A)).subtract(C)).mod(prime);
	    // compute d3
	    di[2] = (((A.multiply(A).mod(prime)).subtract(B))
		    .subtract(D.add(D))).mod(prime);

	    if (k >= 4) {
		E = di[2].multiply(di[2]).mod(prime);
		B = (E.multiply(B.add(D.multiply(new FlexiBigInt(
			java.lang.Integer.toString(3)))))).mod(prime);
		C = (D.multiply(A.add(A).add(C))).mod(prime);
		D = (E.multiply(di[2])).mod(prime);
		A = ((di[2].negate().multiply(A)).subtract(C)).mod(prime);
		// compute d4
		di[3] = ((((A.multiply(A)).mod(prime)).subtract(D)).subtract(B))
			.mod(prime);

		if (k >= 5) {
		    for (int i = 4; i <= k - 1; i++) {
			E = di[i - 1].multiply(di[i - 1]).mod(prime);
			B = (E.multiply(B)).mod(prime);
			C = (D.multiply(C)).mod(prime);
			D = E.multiply(di[i - 1]).mod(prime);
			A = ((di[i - 1].negate().multiply(A)).subtract(C))
				.mod(prime);
			// compute d5, d6, ..., dk
			di[i] = (((A.multiply(A).mod(prime)).subtract(D))
				.subtract(B)).mod(prime);
		    }
		}
	    }
	}
	// Step 2: Simultaneous inversion of d1,..,dk
	ei[0] = di[0];

	for (int i = 1; i <= k - 1; i++) {
	    ei[i] = (ei[i - 1].multiply(di[i])).mod(prime);
	}

	T1 = ei[k - 1].modInverse(prime); // T1 = ei[k-1] hoch -1

	for (int i = k - 1; i >= 1; i--) {
	    T2 = di[i];
	    fi[i] = (ei[i - 1].multiply(T1)).mod(prime);
	    T1 = (T1.multiply(T2)).mod(prime);
	}
	fi[0] = T1;

	// Step 3: Retrieval of the inverses of the delta1,..,deltak

	li[0] = fi[0];
	for (int i = 1; i <= k - 1; i++) {
	    li[i] = ((ei[i - 1].multiply(ei[i - 1]).mod(prime)).multiply(fi[i]))
		    .mod(prime);
	}

	// Step 4: Computation of the required points

	T = (((x.multiply(x).mod(prime).multiply(new FlexiBigInt(
		java.lang.Integer.toString(3)))).add(a)).multiply(li[0]))
		.mod(prime);
	x2 = ((T.multiply(T).mod(prime)).subtract(x.add(x))).mod(prime);
	y2 = ((T.multiply(x.subtract(x2))).subtract(y)).mod(prime);
	T = ((y2.subtract(y)).multiply(li[1])).mod(prime);
	x3 = (((T.multiply(T).mod(prime)).subtract(x2)).subtract(x)).mod(prime);
	y3 = (T.multiply(x2.subtract(x3)).subtract(y2)).mod(prime);

	// points [0] = new PointGFP(x2,y2,el);
	points[0] = p;
	GFPElement gfpx3 = new GFPElement(x3, point.getE().getQ());
	GFPElement gfpy3 = new GFPElement(y3, point.getE().getQ());
	points[1] = new PointGFP(gfpx3, gfpy3, el);

	for (int i = 2; i <= k - 1; i++) {
	    T = ((points[i - 1].getYAffin().toFlexiBigInt().subtract(y2))
		    .multiply(li[i])).mod(prime);
	    xi = ((T.multiply(T).mod(prime)).subtract(x2)).subtract(
		    points[i - 1].getXAffin().toFlexiBigInt()).mod(prime);
	    yi = (T.multiply(x2.subtract(xi)).subtract(y2)).mod(prime);
	    GFPElement gfpxi = new GFPElement(xi, point.getE().getQ());
	    GFPElement gfpyi = new GFPElement(yi, point.getE().getQ());
	    points[i] = new PointGFP(gfpxi, gfpyi, el);
	}

	return points;
    }

    /**
     * This method computes the simultaneous powers <tt>i*P + j*Q</tt>
     * required by the <i>simultaneous 2<sup>w</sup>-ary-method</i>. Since
     * this method uses digits in {0,1,2,...,2<sup>w</sup>-1}, all those
     * simultanteous powers are needed.
     * 
     * @param P
     *                base point
     * @param Q
     *                base point
     * @param w
     *                window size (parameter of the simultaneous 2<sup>w</sup>-ary-method)
     * @return Point matrix with <tt>p[i][j] = i*P + j*Q</tt> for
     *         <tt>i,j = 0,1,2,...,2<sup>w</sup>-1</tt>
     */
    public static Point[][] pre_simultaneous2w(Point P, Point Q, int w) {
	Point[][] r;
	int k = 1 << (w - 1);
	int l = k << 1;
	r = createPointMatrix(P, Q, l, l);
	r[0][0] = createZeroPoint(P, Q, P.getE());

	for (int i = 0, j = i << 1; i < k; i++, j = i << 1) {
	    for (int m = 0, n = m << 1; m < k; m++, n = m << 1) {
		r[j][n] = r[i][m].multiplyBy2();
		r[j][n + 1] = r[j][n].add(Q);
	    }
	    int o = j + 1;
	    for (int m = 0; m < l; m++) {
		r[o][m] = r[o - 1][m].add(P);
	    }
	}
	return r;
    }

    /**
     * This method computes the simultaneous powers <tt>i*P + j*Q</tt>
     * required by the <i>simultaneous sliding window method</i>. Only those
     * powers are computed, where <tt>i</tt> and <tt>j</tt> are not even on
     * the same time. The returned matrix is a subset of the matrix computed by
     * pre_simultaneous2w.
     * 
     * @param P
     *                base point
     * @param Q
     *                base point
     * @param w
     *                window size (parameter of the simultaneous sliding window
     *                method)
     * @return Point matrix <tt>p[i][j] = i*P + j*Q</tt> for <tt>i,j</tt>
     *         not both even and <tt>i,j < 2<sup>w</sup></tt>
     */
    public static Point[][] pre_simultaneousSlidingWindow(Point P, Point Q,
	    int w) {
	int l = 1 << w;
	Point[][] r = new Point[l][l];
	Point p2 = P.multiplyBy2();
	Point q2 = Q.multiplyBy2();

	r[0][0] = createZeroPoint(P, Q, P.getE());
	r[1][0] = P;
	r[0][1] = Q;
	for (int i = 3; i < l; i += 2) {
	    r[0][i] = r[0][i - 2].add(q2);
	    r[i][0] = r[i - 2][0].add(p2);
	}

	for (int i = 1; i < l; i += 2) {
	    for (int j = 1; j < l; j++) {
		r[i][j] = r[i][j - 1].add(Q);
	    }
	}

	for (int i = 2; i < l; i += 2) {
	    for (int j = 1; j < l; j += 2) {
		r[i][j] = r[i - 1][j].add(P);
	    }
	}
	return r;
    }

    /**
     * This method computes the simultaneous powers
     * <tt>i*Q<sub>0</sub> + j*Q<sub>1</sub>, (i,j odd)</tt> required by
     * the Shamir evaluation. In this method, only the use of representations
     * with odd (positive and negative) digits is supported.
     * 
     * @param Q0
     *                base point
     * @param Q1
     *                base point
     * @param w
     *                recoding parameter / upper bound. This parameter will be
     *                used for all points.
     * @return 2-dimensional point matrix <tt>P[i][j]</tt>.<br>
     *         <tt>P[i][.] = i*Q<sub>0</sub> + ...</tt> if <tt>i</tt> is
     *         odd;<br>
     *         <tt>P[i][.] = (-i + 1)Q<sub>0</sub> + ...</tt> if <tt>i</tt>
     *         is even;<br>
     *         <tt>P[0][.] = 0*Q<sub>0</sub> + ...</tt><br>
     *         Example 1: <tt>P[3][4] = 3*Q<sub>0</sub> - 3*Q<sub>1</sub></tt><br>
     *         Example 2: <tt>P[7][5] = 7*Q<sub>0</sub> + 5*Q<sub>1</sub></tt><br>
     *         The scalars <tt>i, j</tt> are restricted to <tt>i, j =
     *         0,+1,-1,...,2<sup>w</sup>-1</tt>,<tt>-2<sup>w</sup>+1</tt>.
     */
    public static Point[][] pre_shamir(Point Q0, Point Q1, int w) {
	int l = (1 << w) + 1;
	Point[][] P = new Point[l][l];
	Point p2 = Q0.multiplyBy2();
	Point q12 = Q1.multiplyBy2();

	P[0][0] = createZeroPoint(Q0, Q1, Q0.getE());
	P[1][0] = Q0;
	P[2][0] = Q0.negate();
	P[0][1] = Q1;
	P[0][2] = Q1.negate();
	for (int i = 3; i < l; i++) {
	    if ((i & 1) == 1) {
		P[0][i] = P[0][i - 2].add(q12);
		P[i][0] = P[i - 2][0].add(p2);
	    } else {
		P[0][i] = P[0][i - 2].subtract(q12);
		P[i][0] = P[i - 2][0].subtract(p2);
	    }
	}
	for (int i = 0; i < l; i++) {
	    for (int j = 0; j < l; j++) {
		if (i != 0 && j != 0) {
		    P[i][j] = P[i][0]; // Initialization as well
		}
	    }
	}
	for (int i = 0; i < l; i++) {
	    for (int j = 0; j < l; j++) {
		if (i != 0 && j != 0) {
		    P[i][j] = P[i][j].add(P[0][j]);
		}
	    }
	}
	return P;
    }

    /**
     * Precomputation in affine coordinates using the Montgomery trick to invert
     * the denominators of all lambdas.<br>
     * This method computes the simultaneous powers
     * <tt>i*Q<sub>0</sub> + j*Q<sub>1</sub></tt> required by the Shamir
     * evaluation. In this method, only the use of representations with odd
     * (positive and negative) digits is supported.
     * 
     * @param q0
     *                base point
     * @param q1
     *                base point
     * @param w
     *                recoding parameter / upper bound
     * @return 2-dimensional point matrix <tt>P[i][j]</tt>.<br>
     *         <tt>P[i][.] = i*Q<sub>0</sub> + ...</tt> if <tt>i</tt> is
     *         odd;<br>
     *         <tt>P[i][.] = (-i + 1)*Q<sub>0</sub> + ...</tt> if <tt>i</tt>
     *         is even;<br>
     *         <tt>P[0][.] = 0*Q<sub>0</sub> + ...</tt><br>
     *         Example 1: <tt>P[3][4] = 3*Q<sub>0</sub> - 3*Q<sub>1</sub></tt><br>
     *         Example 2: <tt>P[7][5] = 7*Q<sub>0</sub> + 5*Q<sub>1</sub></tt><br>
     *         The scalars <tt>i, j</tt> are restricted to <tt>i, j =
     *         0,+1,-1,...,2<sup>w</sup>-1</tt>,<tt>-2<sup>w</sup>+1</tt>.
     */
    public static Point[][] pre_shamirGFP(PointGFP q0, PointGFP q1, int w) {
	int l = (1 << w) + 1;
	PointGFP[][] P = new PointGFP[l][l];
	PointGFP Q0 = (PointGFP) q0.getAffin();
	PointGFP Q1 = (PointGFP) q1.getAffin();
	P[0][0] = new PointGFP((EllipticCurveGFP) Q0.getE());
	Q0.getAffin();
	Q1.getAffin();
	EllipticCurveGFP el = (EllipticCurveGFP) Q1.getE();
	FlexiBigInt prime = el.getQ();

	PointGFP[] temp = precomputationDOS(Q1, 1 << w - 1);
	for (int i = 0; i < temp.length; i++) {
	    P[0][i + i + 1] = temp[i];
	    P[0][i + i + 2] = (PointGFP) temp[i].negate();
	}
	temp = precomputationDOS(Q0, 1 << w - 1);
	for (int i = 0; i < temp.length; i++) {
	    P[i + i + 1][0] = temp[i];
	    P[i + i + 2][0] = (PointGFP) temp[i].negate();
	}

	int k = (l - 1) * (l - 1);
	FlexiBigInt[] delta = new FlexiBigInt[k];
	int z = 0;
	for (int i = 1; i < l; i++) {
	    for (int j = 1; j < l; j++) {
		delta[z] = (P[0][i].getX().toFlexiBigInt().subtract(P[j][0]
			.getX().toFlexiBigInt())).mod(prime);
		z++;
	    }
	}

	FlexiBigInt[] d = new FlexiBigInt[k];
	d[0] = delta[0];
	for (int i = 1; i < d.length; i++) {
	    d[i] = (d[i - 1].multiply(delta[i])).mod(prime);
	}
	FlexiBigInt[] b = new FlexiBigInt[k];
	b[k - 1] = d[k - 1].modInverse(prime);
	FlexiBigInt[] inv = new FlexiBigInt[k];
	for (int i = k - 1; i > 0; i--) {
	    inv[i] = (d[i - 1].multiply(b[i])).mod(prime);
	    b[i - 1] = (b[i].multiply(delta[i])).mod(prime);
	}
	inv[0] = b[0];

	FlexiBigInt[][] lambda = new FlexiBigInt[l - 1][l - 1];
	z = 0;
	FlexiBigInt t;
	for (int i = 0; i < lambda[0].length; i++) {
	    for (int j = 0; j < lambda[0].length; j++) {
		lambda[j][i] = inv[z];
		z++;
	    }
	}
	for (int i = 0; i < lambda[0].length; i++) {
	    for (int j = 0; j < lambda[0].length; j++) {
		t = (P[0][i + 1].getY().toFlexiBigInt().subtract(P[j + 1][0]
			.getY().toFlexiBigInt())).mod(prime);
		lambda[j][i] = (lambda[j][i].multiply(t)).mod(prime);
	    }
	}

	GFPElement x;
	GFPElement y;
	for (int i = 0; i < lambda[0].length; i++) {
	    for (int j = 0; j < lambda[0].length; j++) {
		t = (lambda[i][j].multiply(lambda[i][j])).mod(prime);
		t = (t.subtract(P[i + 1][0].getX().toFlexiBigInt())).mod(prime);
		t = (t.subtract(P[0][j + 1].getX().toFlexiBigInt())).mod(prime);
		x = new GFPElement(t, prime);
		t = (P[i + 1][0].getX().toFlexiBigInt().subtract(t)).mod(prime);
		t = (t.multiply(lambda[i][j])).mod(prime);
		t = (t.subtract(P[i + 1][0].getY().toFlexiBigInt())).mod(prime);
		y = new GFPElement(t, prime);
		P[i + 1][j + 1] = new PointGFP(x, y, el);
	    }
	}
	return P;
    }

    /**
     * This method computes the simultaneous powers
     * <tt>i*Q<sub>0</sub> + j*Q<sub>1</sub>
     * + k*Q<sub>2</sub>, (i,j,k odd)</tt>
     * required by the Shamir evaluation. In this method, only the use of
     * representations with odd (positive and negative) digits is supported.
     * 
     * @param Q0
     *                base point
     * @param Q1
     *                base point
     * @param Q2
     *                base point
     * @param w
     *                recoding parameter / upper bound. This parameter will be
     *                used for all points.
     * @return 3-dimensional point matrix <tt>P[i][j][k]</tt>.<br>
     *         <tt>P[i][.][.] = i*Q<sub>0</sub> + ...</tt> if <tt>i</tt>
     *         is odd;<br>
     *         <tt>P[i][.][.] = (-i + 1)Q<sub>0</sub> + ...</tt> if
     *         <tt>i</tt> is even;<br>
     *         <tt>P[0][.][.] = 0*Q<sub>0</sub> + ...</tt><br>
     *         Example 1:
     *         <tt>P[3][4][5] = 3*Q<sub>0</sub> - 3*Q<sub>1</sub> + 5*Q<sub>2</sub></tt><br>
     *         Example 2:
     *         <tt>7*Q<sub>0</sub> + 5*Q<sub>1</sub> - 3*Q<sub>2</sub></tt>
     *         is stored in P[7][5][4].<br>
     *         The scalars <tt>i, j, k</tt> are restricted to <tt>i, j, k = 
     * 0,+1,-1,...,2<sup>w</sup>-1</tt>,<tt>-2<sup>w</sup>+1</tt>.
     */
    public static Point[][][] pre_shamir(Point Q0, Point Q1, Point Q2, int w) {
	int l = (1 << w) + 1;
	Point[][][] P = new Point[l][l][l];
	Point p2 = Q0.multiplyBy2();
	Point q12 = Q1.multiplyBy2();
	Point q22 = Q2.multiplyBy2();

	P[0][0][0] = createZeroPoint(Q0, Q1, Q0.getE());
	P[1][0][0] = Q0;
	P[2][0][0] = Q0.negate();
	P[0][1][0] = Q1;
	P[0][2][0] = Q1.negate();
	P[0][0][1] = Q2;
	P[0][0][2] = Q2.negate();
	for (int i = 3; i < l; i++) {
	    if ((i & 1) == 1) {
		P[0][0][i] = P[0][0][i - 2].add(q22);
		P[0][i][0] = P[0][i - 2][0].add(q12);
		P[i][0][0] = P[i - 2][0][0].add(p2);
	    } else {
		P[0][0][i] = P[0][0][i - 2].subtract(q22);
		P[0][i][0] = P[0][i - 2][0].subtract(q12);
		P[i][0][0] = P[i - 2][0][0].subtract(p2);
	    }
	}
	for (int i = 0; i < l; i++) {
	    for (int j = 0; j < l; j++) {
		for (int k = 0; k < l; k++) {
		    if (!(i == 0 && j == 0 || j == 0 && k == 0 || i == 0
			    && k == 0)) {
			P[i][j][k] = P[i][0][0]; // Initialization as well
		    }
		}
	    }
	}
	for (int i = 0; i < l; i++) {
	    for (int j = 0; j < l; j++) {
		for (int k = 0; k < l; k++) {
		    if (!(i == 0 && j == 0 || j == 0 && k == 0 || i == 0
			    && k == 0)) {
			P[i][j][k] = P[i][j][k].add(P[0][j][0]);
			P[i][j][k] = P[i][j][k].add(P[0][0][k]);
		    }
		}
	    }
	}
	return P;
    }

    /**
     * This method computes the simultaneous powers
     * <tt>i*Q<sub>0</sub> + j*Q<sub>1</sub> 
     * + k*Q<sub>2</sub> + m*Q<sub>3</sub>, (i,j,k,m odd)</tt>
     * required by the Shamir evaluation. In this method, only the use of
     * representations with odd (positive and negative) digits is supported.
     * 
     * @param Q0
     *                base point
     * @param Q1
     *                base point
     * @param Q2
     *                base point
     * @param Q3
     *                base point
     * @param w
     *                recoding parameter / upper bound. This parameter will be
     *                used for all points.
     * @return 4-dimensional point matrix <tt>P[i][j][k][m]</tt>.<br>
     *         <tt>P[i][.][.][.] = i*Q<sub>0</sub> + ...</tt> if <tt>i</tt>
     *         is odd;<br>
     *         <tt>P[i][.][.][.] = (-i + 1)Q<sub>0</sub> + ...</tt> if
     *         <tt>i</tt> is even;<br>
     *         <tt>P[0][.][.][.] = 0*Q<sub>0</sub> + ...</tt><br>
     *         Example: <tt>P[3][4][5][6] = 3*Q<sub>0</sub> - 3*Q<sub>1</sub> + 
     *         5*Q<sub>2</sub> - 5*Q<sub>3</sub></tt><br>
     *         The scalars <tt>i, j, k, m</tt> are restricted to
     *         <tt>i, j, k, m = 
     * 0,+1,-1,...,2<sup>w</sup>-1</tt>,<tt>-2<sup>w</sup>+1</tt>.
     */
    public static Point[][][][] pre_shamir(Point Q0, Point Q1, Point Q2,
	    Point Q3, int w) {
	int l = (1 << w) + 1;
	Point[][][][] P = new Point[l][l][l][l];
	Point p2 = Q0.multiplyBy2();
	Point q12 = Q1.multiplyBy2();
	Point q22 = Q2.multiplyBy2();
	Point q32 = Q3.multiplyBy2();

	P[0][0][0][0] = createZeroPoint(Q0, Q1, Q0.getE());
	P[1][0][0][0] = Q0;
	P[2][0][0][0] = Q0.negate();
	P[0][1][0][0] = Q1;
	P[0][2][0][0] = Q1.negate();
	P[0][0][1][0] = Q2;
	P[0][0][2][0] = Q2.negate();
	P[0][0][0][1] = Q3;
	P[0][0][0][2] = Q3.negate();
	for (int i = 3; i < l; i++) {
	    if ((i & 1) == 1) {
		P[0][0][0][i] = P[0][0][0][i - 2].add(q32);
		P[0][0][i][0] = P[0][0][i - 2][0].add(q22);
		P[0][i][0][0] = P[0][i - 2][0][0].add(q12);
		P[i][0][0][0] = P[i - 2][0][0][0].add(p2);
	    } else {
		P[0][0][0][i] = P[0][0][0][i - 2].subtract(q32);
		P[0][0][i][0] = P[0][0][i - 2][0].subtract(q22);
		P[0][i][0][0] = P[0][i - 2][0][0].subtract(q12);
		P[i][0][0][0] = P[i - 2][0][0][0].subtract(p2);
	    }
	}
	for (int i = 0; i < l; i++) {
	    for (int j = 0; j < l; j++) {
		for (int k = 0; k < l; k++) {
		    for (int m = 0; m < l; m++) {
			if (!(i == 0 && j == 0 && k == 0 || i == 0 && j == 0
				&& m == 0 || i == 0 && k == 0 && m == 0 || j == 0
				&& k == 0 && m == 0)) {
			    P[i][j][k][m] = P[i][0][0][0]; // Initialization as
			    // well
			}
		    }
		}
	    }
	}
	for (int i = 0; i < l; i++) {
	    for (int j = 0; j < l; j++) {
		for (int k = 0; k < l; k++) {
		    for (int m = 0; m < l; m++) {
			if (!(i == 0 && j == 0 && k == 0 || i == 0 && j == 0
				&& m == 0 || i == 0 && k == 0 && m == 0 || j == 0
				&& k == 0 && m == 0)) {
			    P[i][j][k][m] = P[i][j][k][m].add(P[0][j][0][0]);
			    P[i][j][k][m] = P[i][j][k][m].add(P[0][0][k][0]);
			    P[i][j][k][m] = P[i][j][k][m].add(P[0][0][0][m]);
			}
		    }
		}
	    }
	}
	return P;
    }

    /**
     * LimLee precomputation. Compute the powers <tt>2<sup>l*i</sup>*p</tt> (<tt>i=0, 1,...,n-1</tt>).
     * 
     * @param p
     *                base point
     * @param m
     *                <tt>FlexiBigInt</tt>
     * @param n
     *                LimLee parameter (number of the splitted pieces)
     * @return point array. <tt>P[i] = 2<sup>l*i</sup>*p</tt>
     */
    public static Point[] pre_limlee(Point p, FlexiBigInt m, int n) {
	int length = m.bitLength();
	length = ((length % n) == 0) ? length : (length / n + 1) * n;
	int l = length / n;
	Point[] odd = new Point[n];
	odd[0] = p;

	Point R;
	if (n > 1) {
	    R = (Point) p.clone();
	    for (int j = 1; j < odd.length; j++) {
		for (int i = 0; i < l; i++) {
		    R = R.multiplyBy2();
		}
		odd[j] = R;
	    }
	}

	return odd;
    }

    /**
     * LimLee affine precomputation. This method computes the powers
     * <tt>2<sup>l*i</sup>*p</tt> (<tt>i=0, 1,...,n-1</tt>).
     * 
     * @param p
     *                base point
     * @param m
     *                <tt>FlexiBigInt</tt>
     * @param n
     *                LimLee parameter (number of the splitted pieces)
     * @return point array. <tt>P[i] = 2<sup>l*i</sup>*p</tt>
     */
    public static Point[] pre_limleeAffine(Point p, FlexiBigInt m, int n) {
	int length = m.bitLength();
	length = ((length % n) == 0) ? length : (length / n + 1) * n;
	int l = length / n;
	Point[] odd = new Point[n];
	odd[0] = p;

	Point R;
	if (n > 1) {
	    R = (Point) p.clone();
	    for (int j = 1; j < odd.length; j++) {
		for (int i = 0; i < l; i++) {
		    R = R.multiplyBy2();
		}
		odd[j] = R.getAffin();
	    }
	}

	return odd;
    }

    /**
     * LimLee splitting. This method divides the scalar into <tt>n</tt> pieces
     * of length <tt>l</tt>. if needed, some zeros will be padded on
     * <tt>m</tt>.
     * 
     * @param m
     *                <tt>FlexiBigInt</tt>
     * @param n
     *                LimLee parameter (number of the splitted pieces)
     * @return array of FlexiBigInts s.t.
     *         <tt>m = P[n - 1] ||...||P[1]||P[0]</tt>
     */
    public static FlexiBigInt[] split_limlee(FlexiBigInt m, int n) {
	int length = m.bitLength();
	length = ((length % n) == 0) ? length : (length / n + 1) * n;
	int l = length / n;
	FlexiBigInt[] P = new FlexiBigInt[n];
	FlexiBigInt b = m.abs();
	for (int i = 0; i < n; i++) {
	    FlexiBigInt l1 = b.shiftRight(l).shiftLeft(l);
	    P[i] = b.subtract(l1);
	    b = l1.shiftRight(l);
	}
	if (m.signum() == -1) {
	    for (int i = 0; i < P.length; i++) {
		if (!P[i].equals(FlexiBigInt.ZERO)) {
		    P[i] = P[i].negate();
		}
	    }
	}
	return P;
    }

    // ////////////////////////////////////////////////////////////////////
    // Recoding
    // ////////////////////////////////////////////////////////////////////

    /**
     * Returns <tt>e</tt> as int-array in <i>non-adjacent-form (Naf)</i>.
     * 
     * @param e
     *                the FlexiBigInt that is to be converted
     * @param w
     *                the entries <i>n</i> of the Nafs are smaller than 2<sup>w</sup>
     * @param b
     *                BitLength of <tt>e</tt>
     * 
     * @return <tt>e</tt> in non-adjacent-form as int-array
     */
    public static int[] determineNaf(FlexiBigInt e, int w, int b) {
	int power2wi = 1 << w;
	int j, u;
	int[] N = new int[b + 1];
	FlexiBigInt c = e.abs();
	int s = e.signum();

	j = 0;
	while (c.compareTo(FlexiBigInt.ZERO) > 0) {
	    if (c.testBit(0)) {
		u = (c.intValue()) & ((power2wi << 1) - 1);
		if ((u & power2wi) != 0) {
		    u = u - (power2wi << 1);
		}

		c = c.subtract(FlexiBigInt.valueOf(u));
	    } else {
		u = 0;
	    }

	    N[j++] = (s > 0) ? u : -u;
	    c = c.shiftRight(1);
	}

	// fill with zeros
	while (j <= b) {
	    N[j++] = 0;
	}

	return N;
    }

    /**
     * Returns <tt>e</tt> as int-array in <i>non-adjacent-form (Naf)</i>.
     * 
     * @param e
     *                the FlexiBigInt that is to be converted
     * @param w
     *                the entries <i>n</i> of the Nafs are smaller than 2<sup>w</sup>
     * 
     * @return <tt>e</tt> in non-adjacent-form as int-array
     */
    public static int[] determineNaf(FlexiBigInt e, int w) {
	return determineNaf(e, w, e.bitLength());
    }

    private static void determineNaf(int[] N, FlexiBigInt e, int w) {

	int power2wi = 1 << w;
	int j, u;
	FlexiBigInt c = e.abs();
	int s = e.signum();

	j = 0;
	while (c.compareTo(FlexiBigInt.ZERO) > 0) {
	    if (c.testBit(0)) {
		u = (c.intValue()) & ((power2wi << 1) - 1);
		if ((u & power2wi) != 0) {
		    u = u - (power2wi << 1);
		}
		c = c.subtract(FlexiBigInt.valueOf(u));
	    } else {
		u = 0;
	    }

	    N[j++] = (s > 0) ? u : -u;

	    c = c.shiftRight(1);
	}

	// fill with zeros
	while (j < N.length) {
	    N[j++] = 0;
	}
    }

    /**
     * <i>Right to Left Fixed Size Sliding Window Recoding</i>. This recoding
     * uses digits in {0,1,2,...,2<sup>w</sup>-1} and runs from the LSB to the
     * MSB (Right-to-Left).
     * 
     * @param e
     *                <tt>FlexiBigInt</tt> to be recoded
     * @param w
     *                window size.
     * @return int-array representing the recoding
     */
    public static int[] determineRtlFSSW(FlexiBigInt e, int w) {
	FlexiBigInt m = e.abs();
	int b = m.bitLength();
	int[] fssw = new int[b];
	int i = m.bitLength() - 1;
	int j, s;
	int t = (i + 1) % w;
	if (t != 0) {
	    s = 0;
	    for (j = 0; j < t; j++) {
		s <<= 1;
		if (m.testBit(i - j)) {
		    s++;
		}
	    }
	    fssw[i - t + 1] = s;
	}
	i = i - t;
	while (i >= 0) {
	    s = 0;
	    for (j = i; j > i - w; j--) {
		s <<= 1;
		if (m.testBit(j)) {
		    s++;
		}
	    }
	    if (s > 0) {
		fssw[i - w + 1] = s;
	    }

	    i -= w;
	}
	if (e.signum() == -1) {
	    for (int l = 0; l < fssw.length; l++) {
		if (fssw[l] != 0) {
		    fssw[l] = -fssw[l];
		}
	    }
	}
	return fssw;
    }

    /**
     * <i>Left to Right Fixed Size Sliding Window Recoding</i>. This recoding
     * uses digits in {0,1,2,...,2<sup>w</sup>-1} and runs from the MSB to the
     * LSB (Left-to-Right).
     * 
     * @param e
     *                <tt>FlexiBigInt</tt> to be recoded
     * @param w
     *                window size
     * @return int-array representing the recoding
     */
    public static int[] determineLtrFSSW(FlexiBigInt e, int w) {
	FlexiBigInt m = e.abs();
	int b = m.bitLength();
	int[] fssw = new int[b];
	int i = m.bitLength() - 1;
	int j, s;
	int t = (i + 1) % w;
	while (i + 1 >= w) {
	    s = 0;
	    for (j = i; j > i - w; j--) {
		s <<= 1;
		if (m.testBit(j)) {
		    s++;
		}
	    }
	    if (s > 0) {
		fssw[i - w + 1] = s;
	    }

	    i -= w;
	}
	if (t != 0) {
	    s = 0;
	    for (j = 0; j < t; j++) {
		s <<= 1;
		if (m.testBit(i - j)) {
		    s++;
		}
	    }
	    fssw[0] = s;
	}
	if (e.signum() == -1) {
	    for (int l = 0; l < fssw.length; l++) {
		if (fssw[l] != 0) {
		    fssw[l] = -fssw[l];
		}
	    }
	}
	return fssw;
    }

    /**
     * <i>Sliding Window Recoding</i>. This is a Left-to-Right method using the
     * digits {0, 1, 3,..., 2<sup>w</sup> - 1}.
     * 
     * @param e
     *                <tt>FlexiBigInt</tt> to be recoded
     * @param w
     *                window size
     * @return int-array representing the recoding
     */
    public static int[] determineSW(FlexiBigInt e, int w) {
	FlexiBigInt m = e.abs();
	int b = m.bitLength();
	int[] sw = new int[b];
	int i = m.bitLength() - 1;
	int j, k, s;
	while (i >= 0) {
	    if (!m.testBit(i)) {
		i--;
	    } else {
		k = ((i - w) > -1) ? (i - w) : -1;
		j = k + 1;
		while (!m.testBit(j)) {
		    j++; // i >= j >= 0
		}
		s = 0;
		for (int p = i; p >= j; p--) {
		    s <<= 1;
		    if (m.testBit(p)) {
			s++;
		    }
		}
		sw[j] = s;
		i -= i - j + 1;
	    }
	}
	if (e.signum() == -1) {
	    for (int l = 0; l < sw.length; l++) {
		if (sw[l] != 0) {
		    sw[l] = -sw[l];
		}
	    }
	}
	return sw;
    }

    /**
     * <i>Right to Left Signed Fractional Window Method</i> proposed in
     * [Moe04]. The occuring digits are {0, 1, -1, 3, -3,..., m, -m} (m must be
     * odd!).
     * 
     * @param e
     *                <tt>FlexiBigInt</tt> to be recoded
     * @param m
     *                odd integer
     * @return int-array representing the recoding
     */
    public static int[] determineRtlSFW(FlexiBigInt e, int m) {
	if ((m & 1) == 0) {
	    throw new RuntimeException("Parameter m must be odd");
	}

	FlexiBigInt b1 = e.abs();
	int b = b1.bitLength();
	int[] sfw = new int[b + 1];
	int i = 0;
	FlexiBigInt bm = new FlexiBigInt(java.lang.Integer.toString(m));
	int wm = bm.bitLength();
	int Wm = wm + 1;
	int D = b1.mod(new FlexiBigInt(java.lang.Integer.toString(1 << Wm)))
		.intValue();
	int d;
	while (D != 0 || i + wm < b) {
	    int x = D % (1 << Wm);
	    if ((x & 1) == 0) {
		d = 0;
	    } else if (0 < x && x <= m) {
		d = x;
	    } else if (m < x && x < (1 << Wm) - m) {
		d = x - (1 << wm);
	    } else {
		d = x - (1 << Wm);
	    }
	    sfw[i] = d;
	    i++;
	    int bit = b1.testBit(i + wm) ? 1 : 0;
	    D = (bit << wm) + (D - d) / 2;
	}
	if (e.signum() == -1) {
	    for (int j = 0; j < sfw.length; j++) {
		if (sfw[j] != 0) {
		    sfw[j] = -sfw[j];
		}
	    }
	}
	return sfw;
    }

    /**
     * <i>Left to Right Signed Fractional Window Method</i> proposed in
     * [Moe04]. The occuring digits are {0, 1, -1, 3, -3,..., m, -m} (m must be
     * odd!).
     * 
     * @param e
     *                <tt>FlexiBigInt</tt> to be recoded
     * @param m
     *                odd integer
     * @return int-array representing the recoding
     */
    public static int[] determineLtrSFW(FlexiBigInt e, int m) {
	if ((m & 1) == 0) {
	    throw new RuntimeException("Parameter m must be odd");
	}

	FlexiBigInt b1 = e.abs();
	int b = b1.bitLength();
	int[] sfw = new int[b + 1];
	int[] b2 = new int[b + 3];
	for (int i = 0; i < b; i++) {
	    b2[i] = b1.testBit(i) ? 1 : 0;
	}
	FlexiBigInt bm = new FlexiBigInt(java.lang.Integer.toString(m));
	int wm = bm.bitLength();
	int Wm = wm + 1;

	int i = b + 2;
	int l = 0;
	int W;
	while (i >= 0) {
	    if (i >= 1 && b2[i] == b2[i - 1] || i == 0 && b2[0] == 0) {
		i--;
	    } else {
		W = Wm;
		int[] temp = new int[W];
		if (i - W + 1 >= 0) {
		    System.arraycopy(b2, i - W + 1, temp, 0, W);
		} else {
		    System.arraycopy(b2, 0, temp, W - i - 1, i + 1);
		}
		temp[W - 1] = -temp[W - 1];
		int d = 0;
		int t = 1;
		for (int z = 0; z < temp.length; z++) {
		    if (temp[z] != 0) {
			d = temp[z] * t + d;
			t <<= 1;
		    } else {
			t <<= 1;
		    }
		}
		if (i >= W) {
		    d += b2[i - W];
		}
		if ((d & 1) == 1 && (d > m || -d > m)) {
		    W = wm;
		    temp = new int[W];
		    if (i - W + 1 >= 0) {
			System.arraycopy(b2, i - W + 1, temp, 0, W);
		    } else {
			System.arraycopy(b2, 0, temp, W - i - 1, i + 1);
		    }
		    temp[W - 1] = -temp[W - 1];
		    d = 0;
		    t = 1;
		    for (int z = 0; z < temp.length; z++) {
			if (temp[z] != 0) {
			    d = temp[z] * t + d;
			    t <<= 1;
			} else {
			    t <<= 1;
			}
		    }
		    if (i >= W) {
			d += b2[i - W];
		    }
		}
		int nexti = i - W;
		i = nexti + 1;
		while ((d & 1) == 0) {
		    i++;
		    d >>= 1;
		}
		if (i >= 0) {
		    sfw[i] = d;
		}

		if (i > l) {
		    l = i;
		}
		i = nexti;
	    }
	}
	if (e.signum() == -1) {
	    for (int j = 0; j < sfw.length; j++) {
		if (sfw[j] != 0) {
		    sfw[j] = -sfw[j];
		}
	    }
	}
	return sfw;
    }

    /**
     * Computes the lookup-table [OSST04, Appendix B] for the wMOF-recoding. For
     * every decimal value <tt>c</tt> of a possible MOF-Recoding, there exist
     * integers gamma and xi with <tt>c=gamma*2<sup>xi</sup></tt>. They can
     * be computed with this method.
     * 
     * @param w
     *                window width (parameter of wMOF)
     * @return 2-lined matrix. line 0: gamma[i]; line 1: xi[i].
     */
    private static int[][] getMofTable(int w) {
	int[][] table = new int[2][1 << w];
	int h = 1 << (w - 1);
	int c, z;
	final int cd = (1 << w) - 1;
	for (int d = h; d < 3 * h; d++) {
	    c = (d & cd) - (d >> 1);
	    z = d - (1 << (w - 1));
	    table[1][z] = 0;
	    while ((c & 1) == 0) {
		table[1][z]++;
		c >>= 1;
	    }
	    table[0][z] = c;
	}
	return table;
    }

    /**
     * Returns the <i>Width-w Mutual Opposite Form (wMOF)</i> of <tt>d</tt>
     * proposed in [OSST04, Appendix B]. This recoding uses digits in {0, 1, -1,
     * 3, -3,..., 2<sup>w - 1</sup> - 1}.
     * 
     * @param d
     *                <tt>FlexiBigInt</tt> to be recoded
     * @param w
     *                window width (parameter of wMOF)
     * @return int-array representing the recoding
     */
    public static int[] determineMof(FlexiBigInt d, int w) {
	int n = d.bitLength() + 1;
	int[] mof = new int[n];
	int[][] table = getMofTable(w);
	int i = n;
	int index;
	FlexiBigInt indexl;
	FlexiBigInt indexr;
	while (i > 0) {
	    if (d.testBit(i) != d.testBit(i - 1)) {
		indexl = d.shiftRight(i - w);
		indexr = new FlexiBigInt(java.lang.Integer
			.toString((1 << (w + 1)) - 1));
		index = indexl.and(indexr).intValue() - (1 << (w - 1));
		mof[i - w + 1 + table[1][index]] = table[0][index];
		i -= w;
	    } else {
		i--;
	    }
	}
	if (i == 0 && d.testBit(0)) {
	    mof[0] = -1;
	}
	return mof;
    }

    /**
     * Returns the <i>Mutual Opposite Form (MOF)</i> of <tt>d</tt> proposed
     * in [OSST04, Alg. 2]. All digits are in {0, 1, -1}.
     * 
     * @param d
     *                <tt>FlexiBigInt</tt> to be recoded
     * @return int-array representing the recoding
     */
    public static int[] determineMof(FlexiBigInt d) {
	FlexiBigInt e = d.abs();
	int n = e.bitLength();
	int[] mof = new int[n + 1];
	if (e.equals(FlexiBigInt.ZERO)) {
	    return mof;
	}
	if (e.testBit(n - 1)) {
	    mof[n] = 1;
	}
	for (int i = n - 1; i > 0; i--) {
	    if (e.testBit(i) && !e.testBit(i - 1)) {
		mof[i] = -1;
	    }
	    if (!e.testBit(i) && e.testBit(i - 1)) {
		mof[i] = 1;
	    }
	}
	if (e.testBit(0)) {
	    mof[0] = -1;
	}
	if (d.signum() == -1) {
	    for (int l = 0; l < mof.length; l++) {
		if (mof[l] != 0) {
		    mof[l] = -mof[l];
		}
	    }
	}
	return mof;
    }

    /**
     * Returns the <i>Joint Sparse Form</i> of d<sub>0</sub> to d<sub>k</sub>
     * using algorithm 3 [PRO03]. This recoding uses digits in {0, 1, -1}.
     * 
     * @param d
     *                Array of <tt>FlexiBigInt</tt>
     * @return int-matrix.<br>
     *         line i contains the recoded representation of d<sub>i</sub>.
     */
    public static int[][] determineJsf(FlexiBigInt[] d) {
	FlexiBigInt[] D = new FlexiBigInt[d.length];
	for (int i = 0; i < D.length; i++) {
	    D[i] = d[i].abs();
	}

	int h = D.length;
	int a = 0;
	for (int i = 0; i < h; i++) {
	    a = (a < D[i].bitLength()) ? D[i].bitLength() : a;
	}
	int[][] T = new int[h][a + 1];
	for (int i = 0; i < h; i++) {
	    for (int j = 0; j < D[i].bitLength(); j++) {
		if (D[i].testBit(j)) {
		    T[i][j] = 1;
		}
	    }
	}

	int y = 0;
	int[] badrows = new int[h];
	for (int i = 0; i < h; i++) {
	    badrows[i] = 1;
	}
	int[] zerocolumns = new int[a + 1];
	while (y <= a) {
	    int flag = 1;
	    for (int i = 0; i < h; i++) {
		if (badrows[i] != 0 && T[i][y] != 0) {
		    badrows[i] = 0;
		    flag = 0;
		}
	    }
	    if (flag == 1) {
		zerocolumns[y] = 1;
		for (int i = 0; i < h; i++) {
		    badrows[i] = 1;
		}
		for (int i = 0; i < h; i++) {
		    int j;
		    if (T[i][y] == 1) {
			T[i][y] = 0;
			j = y - 1;
			while (T[i][j] == 0) {
			    j--;
			}
			int m;
			if (T[i][j] == 1) {
			    m = y + 1;
			    while (T[i][m] == 1) {
				T[i][m] = 0;
				m++;
			    }
			    T[i][m]++;
			    m = y - 1;
			    while (T[i][m] == 0) {
				T[i][m] = -1;
				m--;
			    }
			    T[i][m] = -1;
			} else if (T[i][j] == -1) {
			    m = y - 1;
			    while (T[i][m] == 0) {
				T[i][m] = 1;
				m--;
			    }
			    T[i][m] = 1;
			}
		    } else if (T[i][y] == -1) {
			T[i][y] = 0;
			j = y - 1;
			while (T[i][j] == 0) {
			    j--;
			}
			int m;
			if (T[i][j] == 1) {
			    m = y - 1;
			    while (T[i][m] == 0) {
				T[i][m] = -1;
				m--;
			    }
			    T[i][m] = -1;
			} else if (T[i][j] == -1) {
			    m = y + 1;
			    while (T[i][m] == -1) {
				T[i][m] = 0;
				m++;
			    }
			    T[i][m]--;
			    m = y - 1;
			    while (T[i][m] == 0) {
				T[i][m] = 1;
				m--;
			    }
			    T[i][m] = 1;
			}
		    }
		}
	    }
	    y++;
	}

	for (int i = 0; i < h; i++) {
	    int j = 0;
	    while (j < a) {
		while (j <= a && T[i][j] == 0) {
		    j++;
		}
		if (j < a && T[i][j] * T[i][j + 1] == -1) {
		    T[i][j] = -T[i][j];
		    T[i][j + 1] = 0;
		    j += 2;
		} else if (j < a && T[i][j] == T[i][j + 1]) {
		    int z = j + 1;
		    while (z < a && T[i][j] == T[i][z + 1]) {
			z++;
		    }
		    if (z < a && T[i][z + 1] == 0 && zerocolumns[z + 1] == 0) {
			T[i][z + 1] = T[i][j];
			for (int k = j + 1; k <= z; k++) {
			    T[i][k] = 0;
			}
			T[i][j] = -T[i][j];
		    } else if (z < a && T[i][z + 1] == -T[i][j]) {
			for (int k = j + 1; k <= z + 1; k++) {
			    T[i][k] = 0;
			}
			T[i][j] = -T[i][j];
		    }
		    j = z + 1;
		} else {
		    j += 2;
		}
	    }
	}

	for (int i = 0; i < D.length; i++) {
	    if (d[i].signum() == -1) {
		for (int j = 0; j < T[i].length; j++) {
		    if (T[i][j] != 0) {
			T[i][j] = -T[i][j];
		    }
		}
	    }
	}
	return T;
    }

    /**
     * Algorithm 4 [DOT07]
     */
    private static int[] calculateZ(int[] m0, int[] m1, int c) {
	int k = (m0.length > m1.length) ? m0.length : m1.length;
	int[] z = new int[k];
	int f0, f1;
	f0 = -1;
	for (int j = k - 1; j >= 0; j--) {
	    if (m0[j] != 0) {
		f0 = j;
	    }
	}
	f1 = -1;
	for (int j = k - 1; j >= 0; j--) {
	    if (m1[j] != 0) {
		f1 = j;
	    }
	}
	int r = 0;
	for (int j = k - 1; j >= 0; j--) {
	    if (j == f0 || j == f1 || r == 2) {
		z[j] = 0;
		r = 0;
	    } else {
		z[j] = 1;
		r++;
	    }
	    if (c == 0 && j == k - 1 && z[k - 1] == 1) {
		r = 2;
	    }
	}
	return z;
    }

    /**
     * Algorithm 5 [DOT07]
     */
    private static void convert(int[] m0, int[] m1, int[] z) {
	int k = (m0.length > m1.length) ? m0.length : m1.length;
	int s;
	for (int j = k - 1; j >= 0; j--) {
	    if (z[j] == 1 && m0[j] != 0) {
		s = j - 1;
		while (m0[s] == 0) {
		    s--;
		}
		if (m0[j] == -m0[s]) {
		    for (int t = j - 1; t >= s; t--) {
			m0[t] = m0[j];
		    }
		    m0[j] = 0;
		} else if (m0[j] == m0[s]) {
		    for (int t = j - 2; t >= s; t--) {
			m0[t] = -m0[j];
		    }
		    m0[j - 1] = 3 * m0[j];
		    m0[j] = 0;
		}
	    }
	}
	for (int j = k - 1; j >= 0; j--) {
	    if (z[j] == 1 && m1[j] != 0) {
		s = j - 1;
		while (m1[s] == 0) {
		    s--;
		}
		if (m1[j] == -m1[s]) {
		    for (int t = j - 1; t >= s; t--) {
			m1[t] = m1[j];
		    }
		    m1[j] = 0;
		} else if (m1[j] == m1[s]) {
		    for (int t = j - 2; t >= s; t--) {
			m1[t] = -m1[j];
		    }
		    m1[j - 1] = 3 * m1[j];
		    m1[j] = 0;
		}
	    }
	}
    }

    /**
     * Returns the <i>w3-Joint Sparse Form</i> (w3-JSF) of e<sub>0</sub> and
     * e<sub>1</sub> using Algorithm 3 [DOT07].<br>
     * The scalars e<sub>0</sub> and e<sub>1</sub> must have the same
     * bitlength!<br>
     * Occuring digits are {0, 1, -1, 3, -3}.
     * 
     * @param e0
     *                <tt>FlexiBigInt</tt>
     * @param e1
     *                <tt>FlexiBigInt</tt>
     * @return 2-lined matrix.<br>
     *         line 0 contains the recoded representation of e<sub>0</sub>;<br>
     *         line 1 contains the recoded representation of e<sub>1</sub>.
     */
    public static int[][] determineW3Jsf(FlexiBigInt e0, FlexiBigInt e1) {
	FlexiBigInt d0 = e0.abs();
	FlexiBigInt d1 = e1.abs();

	int n = d0.bitLength();
	if (d1.bitLength() != n) {
	    throw new RuntimeException(
		    "e0 and e1 don't have the same bitlength");
	}

	int[][] m = new int[2][n + 1];
	int u = n;
	int c = 1;
	while (u > 0) {
	    while (u > 0 && d0.testBit(u) == d0.testBit(u - 1)
		    && d1.testBit(u) == d1.testBit(u - 1)) {
		m[0][u] = 0;
		m[1][u] = 0;
		u--;
		c = 1;
	    }
	    int l = u - 1 - c;
	    for (int i = l; i <= u - 1 + c; i++) {
		if (i < n && i > 0) {
		    if (d0.testBit(i) && !d0.testBit(i - 1)) {
			m[0][i] = -1;
		    }
		    if (!d0.testBit(i) && d0.testBit(i - 1)) {
			m[0][i] = 1;
		    }
		    if (d1.testBit(i) && !d1.testBit(i - 1)) {
			m[1][i] = -1;
		    }
		    if (!d1.testBit(i) && d1.testBit(i - 1)) {
			m[1][i] = 1;
		    }
		} else if (i == n) {
		    m[0][n] = 1;
		    m[1][n] = 1;
		} else if (i == 0) {
		    if (d0.testBit(i)) {
			m[0][0] = -1;
		    }
		    if (d1.testBit(i)) {
			m[1][0] = -1;
		    }
		}
	    }
	    int[] tmp0 = new int[u - l + 1];
	    int[] tmp1 = new int[u - l + 1];
	    if (l >= 0) {
		System.arraycopy(m[0], l, tmp0, 0, u - l + 1);
		System.arraycopy(m[1], l, tmp1, 0, u - l + 1);
	    } else {
		System.arraycopy(m[0], 0, tmp0, -l, u + 1);
		System.arraycopy(m[1], 0, tmp1, -l, u + 1);
	    }
	    int[] z = calculateZ(tmp0, tmp1, c);
	    int sum = 0;
	    for (int i = 0; i <= u - l; i++) {
		sum += z[i];
	    }
	    if (sum >= 1 + c || l <= 0) {
		convert(tmp0, tmp1, z);
		if (l >= 0) {
		    System.arraycopy(tmp0, 0, m[0], l, u - l + 1);
		    System.arraycopy(tmp1, 0, m[1], l, u - l + 1);
		} else {
		    System.arraycopy(tmp0, -l, m[0], 0, u + 1);
		    System.arraycopy(tmp1, -l, m[1], 0, u + 1);
		}
		u -= 2 + c;
		c = 1;
		if (u == 0) {
		    if (d0.testBit(0)) {
			m[0][0] = -1;
		    }
		    if (d1.testBit(0)) {
			m[1][0] = -1;
		    }
		}
	    } else {
		l = u - 3 - c;
		for (int i = l; i <= u - 1 + c; i++) {
		    if (i < n && i > 0) {
			if (d0.testBit(i) && !d0.testBit(i - 1)) {
			    m[0][i] = -1;
			}
			if (!d0.testBit(i) && d0.testBit(i - 1)) {
			    m[0][i] = 1;
			}
			if (d1.testBit(i) && !d1.testBit(i - 1)) {
			    m[1][i] = -1;
			}
			if (!d1.testBit(i) && d1.testBit(i - 1)) {
			    m[1][i] = 1;
			}
		    } else if (i == n) {
			m[0][n] = 1;
			m[1][n] = 1;
		    } else if (i == 0) {
			if (d0.testBit(i)) {
			    m[0][0] = -1;
			}
			if (d1.testBit(i)) {
			    m[1][0] = -1;
			}
		    }
		}
		tmp0 = new int[u - l + 1];
		tmp1 = new int[u - l + 1];
		if (l >= 0) {
		    System.arraycopy(m[0], l, tmp0, 0, u - l + 1);
		    System.arraycopy(m[1], l, tmp1, 0, u - l + 1);
		} else {
		    System.arraycopy(m[0], 0, tmp0, -l, u + 1);
		    System.arraycopy(m[1], 0, tmp1, -l, u + 1);
		}
		z = calculateZ(tmp0, tmp1, c);
		if (z[3] == 1 && z[2] == 0 && z[1] == 1 && z[0] == 0) {
		    convert(tmp0, tmp1, z);
		    if (l >= 0) {
			System.arraycopy(tmp0, 0, m[0], l, u - l + 1);
			System.arraycopy(tmp1, 0, m[1], l, u - l + 1);
		    } else {
			System.arraycopy(tmp0, -l, m[0], 0, u + 1);
			System.arraycopy(tmp1, -l, m[1], 0, u + 1);
		    }
		    u -= 4 + c;
		    c = 1;
		} else {
		    l = u - 2 - c;
		    for (int i = l; i <= u - 1 + c; i++) {
			if (i < n && i > 0) {
			    if (d0.testBit(i) && !d0.testBit(i - 1)) {
				m[0][i] = -1;
			    }
			    if (!d0.testBit(i) && d0.testBit(i - 1)) {
				m[0][i] = 1;
			    }
			    if (d1.testBit(i) && !d1.testBit(i - 1)) {
				m[1][i] = -1;
			    }
			    if (!d1.testBit(i) && d1.testBit(i - 1)) {
				m[1][i] = 1;
			    }
			} else if (i == n) {
			    m[0][n] = 1;
			    m[1][n] = 1;
			} else if (i == 0) {
			    if (d0.testBit(i)) {
				m[0][0] = -1;
			    }
			    if (d1.testBit(i)) {
				m[1][0] = -1;
			    }
			}
		    }
		    tmp0 = new int[u - l + 1];
		    tmp1 = new int[u - l + 1];
		    if (l >= 0) {
			System.arraycopy(m[0], l, tmp0, 0, u - l + 1);
			System.arraycopy(m[1], l, tmp1, 0, u - l + 1);
		    } else {
			System.arraycopy(m[0], 0, tmp0, -l, u + 1);
			System.arraycopy(m[1], 0, tmp1, -l, u + 1);
		    }
		    z = calculateZ(tmp0, tmp1, c);
		    convert(tmp0, tmp1, z);
		    if (l >= 0) {
			System.arraycopy(tmp0, 0, m[0], l, u - l + 1);
			System.arraycopy(tmp1, 0, m[1], l, u - l + 1);
		    } else {
			System.arraycopy(tmp0, -l, m[0], 0, u + 1);
			System.arraycopy(tmp1, -l, m[1], 0, u + 1);
		    }
		    int[] left0 = new int[2];
		    int[] left1 = new int[2];
		    System.arraycopy(m[0], l, left0, 0, 2);
		    System.arraycopy(m[1], l, left1, 0, 2);
		    int[] right0 = new int[2];
		    int[] right1 = new int[2];
		    if (l < n && l > 0) {
			if (d0.testBit(l) && !d0.testBit(l - 1)) {
			    right0[0] = -1;
			}
			if (!d0.testBit(l) && d0.testBit(l - 1)) {
			    right0[0] = 1;
			}
			if (d1.testBit(l) && !d1.testBit(l - 1)) {
			    right1[0] = -1;
			}
			if (!d1.testBit(l) && d1.testBit(l - 1)) {
			    right1[0] = 1;
			}
		    } else if (l == n) {
			right0[0] = 1;
			right1[0] = 1;
		    } else if (l == 0) {
			if (d0.testBit(l)) {
			    right0[0] = -1;
			}
			if (d1.testBit(l)) {
			    right1[0] = -1;
			}
		    }
		    if (l - 1 < n && l - 1 > 0) {
			if (d0.testBit(l - 1) && !d0.testBit(l - 2)) {
			    right0[1] = -1;
			}
			if (!d0.testBit(l - 1) && d0.testBit(l - 2)) {
			    right0[1] = 1;
			}
			if (d1.testBit(l - 1) && !d1.testBit(l - 2)) {
			    right1[1] = -1;
			}
			if (!d1.testBit(l - 1) && d1.testBit(l - 2)) {
			    right1[1] = 1;
			}
		    } else if (l - 1 == n) {
			right0[1] = 1;
			right1[1] = 1;
		    } else if (l - 1 == 0) {
			if (d0.testBit(l)) {
			    right0[0] = -1;
			}
			if (d1.testBit(l)) {
			    right1[0] = -1;
			}
		    }
		    if (right0.equals(left0) && right1.equals(left1)) {
			u -= 1 + c;
			c = 1;
		    } else if ((m[0][l] != -3 || m[0][l] == 3)
			    && (m[1][l] != -3 || m[1][l] == 3)
			    && (m[0][l] == 0 && m[1][l] == 0)) {
			u -= 2 + c;
			c = 0;
		    } else {
			u -= 3 + c;
			c = 1;
		    }

		}
	    }

	}

	if (e0.signum() == -1) {
	    for (int i = 0; i < m[0].length; i++) {
		if (m[0][i] != 0) {
		    m[0][i] = -m[0][i];
		}
	    }
	}
	if (e1.signum() == -1) {
	    for (int i = 0; i < m[1].length; i++) {
		if (m[1][i] != 0) {
		    m[1][i] = -m[1][i];
		}
	    }
	}
	return m;
    }

    /**
     * Returns the <i>simultaneous2w recoding (Right to Left)</i>. The separate
     * recodings are equal to
     * {@link #determineRtlFSSW(FlexiBigInt e, int w) determineRtlFSSW}.
     * 
     * @param d1
     *                <tt>FlexiBigInt</tt>
     * @param d2
     *                <tt>FlexiBigInt</tt>
     * @param w
     *                window size
     * @return 2-lined matrix.<br>
     *         line 0 contains the recoded representation of d<sub>1</sub>;<br>
     *         line 1 contains the recoded representation of d<sub>2</sub>.
     */
    public static int[][] determineSimultaneous2w_rtl(FlexiBigInt d1,
	    FlexiBigInt d2, int w) {
	FlexiBigInt e1 = d1.abs();
	FlexiBigInt e2 = d2.abs();
	int b1 = e1.bitLength();
	int b2 = e2.bitLength();
	int b = (b1 < b2) ? b2 : b1;
	int[][] N = new int[2][b];
	int i = b - 1;
	int j, s1, s2;
	int t = (i + 1) % w;
	if (t != 0) {
	    s1 = 0;
	    s2 = 0;
	    for (j = 0; j < t; j++) {
		s1 <<= 1;
		s2 <<= 1;
		if (e1.testBit(i - j)) {
		    s1++;
		}
		if (e2.testBit(i - j)) {
		    s2++;
		}
	    }
	    N[0][i - t + 1] = s1;
	    N[1][i - t + 1] = s2;
	}
	i = i - t;
	while (i >= 0) {
	    s1 = 0;
	    s2 = 0;
	    for (j = i; j > i - w; j--) {
		s1 <<= 1;
		s2 <<= 1;
		if (e1.testBit(j)) {
		    s1++;
		}
		if (e2.testBit(j)) {
		    s2++;
		}
	    }
	    if (s1 + s2 > 0) {
		N[0][i - w + 1] = s1;
		N[1][i - w + 1] = s2;
	    }

	    i -= w;
	}

	if (d1.signum() == -1) {
	    for (int l = 0; l < N[0].length; l++) {
		if (N[0][l] != 0) {
		    N[0][l] = -N[0][l];
		}
	    }
	}
	if (d2.signum() == -1) {
	    for (int l = 0; l < N[1].length; l++) {
		if (N[1][l] != 0) {
		    N[1][l] = -N[1][l];
		}
	    }
	}
	return N;
    }

    /**
     * Returns the <i>simultaneous2w recoding (Left to Right)</i>. If d<sub>1</sub>
     * and d<sub>2</sub> have the same bitlength, the separate recodings are
     * equal to {@link #determineLtrFSSW(FlexiBigInt e, int w) determineLtrFSSW}.
     * 
     * @param d1
     *                <tt>FlexiBigInt</tt>
     * @param d2
     *                <tt>FlexiBigInt</tt>
     * @param w
     *                window size
     * @return 2-lined matrix.<br>
     *         line 0 contains the recoded representation of d<sub>1</sub>;<br>
     *         line 1 contains the recoded representation of d<sub>2</sub>.
     */
    public static int[][] determineSimultaneous2w_ltr(FlexiBigInt d1,
	    FlexiBigInt d2, int w) {
	FlexiBigInt e1 = d1.abs();
	FlexiBigInt e2 = d2.abs();
	int b1 = e1.bitLength();
	int b2 = e2.bitLength();
	int b = (b1 < b2) ? b2 : b1;
	int[][] N = new int[2][b];
	int i = b - 1;
	int j, s1, s2;
	int t = (i + 1) % w;
	while (i + 1 >= w) {
	    s1 = 0;
	    s2 = 0;
	    for (j = i; j > i - w; j--) {
		s1 <<= 1;
		s2 <<= 1;
		if (e1.testBit(j)) {
		    s1++;
		}
		if (e2.testBit(j)) {
		    s2++;
		}
	    }
	    if (s1 + s2 > 0) {
		N[0][i - w + 1] = s1;
		N[1][i - w + 1] = s2;
	    }

	    i -= w;
	}
	if (t != 0) {
	    s1 = 0;
	    s2 = 0;
	    for (j = 0; j < t; j++) {
		s1 <<= 1;
		s2 <<= 1;
		if (e1.testBit(i - j)) {
		    s1++;
		}
		if (e2.testBit(i - j)) {
		    s2++;
		}
	    }
	    N[0][0] = s1;
	    N[1][0] = s2;
	}

	if (d1.signum() == -1) {
	    for (int l = 0; l < N[0].length; l++) {
		if (N[0][l] != 0) {
		    N[0][l] = -N[0][l];
		}
	    }
	}
	if (d2.signum() == -1) {
	    for (int l = 0; l < N[1].length; l++) {
		if (N[1][l] != 0) {
		    N[1][l] = -N[1][l];
		}
	    }
	}
	return N;
    }

    /**
     * Returns the <I>simultaneous sliding window recoding</i>. Attention: The
     * result does not coincide with the classical sliding window method. Even
     * digits may occur.<br>
     * A special precomputation can be found
     * {@link #pre_simultaneousSlidingWindow(Point P, Point Q, int w) here}.
     * 
     * @param d1
     *                <tt>FlexiBigInt</tt>
     * @param d2
     *                <tt>FlexiBigInt</tt>
     * @param w
     *                window size
     * @return 2-lined matrix.<br>
     *         line 0 contains the recoded representation of d<sub>1</sub>;<br>
     *         line 1 contains the recoded representation of d<sub>2</sub>.
     */
    public static int[][] determineSimultaneousSW(FlexiBigInt d1,
	    FlexiBigInt d2, int w) {
	FlexiBigInt e1 = d1.abs();
	FlexiBigInt e2 = d2.abs();
	int b1 = e1.bitLength();
	int b2 = e2.bitLength();
	int b = (b1 < b2) ? b2 : b1;
	int[][] sw = new int[2][b + 1];
	int jNew = 0;
	int J = 0;
	int s1, s2, i;
	int j = b - 1;
	while (j >= 0) {
	    if (!e1.testBit(j) && !e2.testBit(j)) {
		j--;
	    } else {
		jNew = ((j - w) > -1) ? (j - w) : -1;
		J = jNew + 1;

		while (!e1.testBit(J) && !e2.testBit(J)) {
		    J++;
		}
		s1 = 0;
		s2 = 0;
		for (i = j; i >= J; i--) {
		    s1 <<= 1;
		    s2 <<= 1;
		    if (e1.testBit(i)) {
			s1++;
		    }
		    if (e2.testBit(i)) {
			s2++;
		    }
		}
		sw[0][J] = s1;
		sw[1][J] = s2;
		j -= j - J + 1;
	    }
	}

	if (d1.signum() == -1) {
	    for (int l = 0; l < sw[0].length; l++) {
		if (sw[0][l] != 0) {
		    sw[0][l] = -sw[0][l];
		}
	    }
	}
	if (d2.signum() == -1) {
	    for (int l = 0; l < sw[1].length; l++) {
		if (sw[1][l] != 0) {
		    sw[1][l] = -sw[1][l];
		}
	    }
	}
	return sw;
    }

    /**
     * returns the <i>Naf</i>-representations of the FlexiBigInts stored in
     * <tt>e</tt> in one matrix.
     * 
     * @param e
     *                array of FlexiBigInts to be recoded
     * @param w
     *                wNaf parameters. For the recoding of e[i], w[i] will be
     *                used.
     * @return matrix. Line i contains the wNaf-representation of
     *         <tt>e<sub>i</sub></tt>.
     */
    public static int[][] determineSimultaneousNaf(FlexiBigInt[] e, int[] w) {
	int b = 0;
	for (int i = 0; i < e.length; i++) {
	    b = (b < e[i].bitLength()) ? e[i].bitLength() : b;
	}

	int[][] N = new int[e.length][b + 1];

	for (int i = 0; i < e.length; i++) {
	    determineNaf(N[i], e[i], w[i]);
	}
	return N;
    }

    // ////////////////////////////////////////////////////////////////////
    // Evaluation
    // ////////////////////////////////////////////////////////////////////

    /**
     * Square and multiply evaluation without recoding. This is also known by
     * <i>binary method</i> or <i>fast exponentiation</i>. This method returns
     * <tt>m*p</tt>.
     * 
     * @param m
     *                <tt>FlexiBigInt</tt>
     * @param p
     *                base point
     * @return <tt>m*p</tt>
     */
    public static Point eval_SquareMultiply(FlexiBigInt m, Point p) {
	Point P = (Point) p.clone();
	Point H = createZeroPoint(p, p, p.getE());

	if (m.compareTo(FlexiBigInt.ZERO) == -1) { // if m < 0
	    m = m.negate(); // m = -m
	    P = P.negate(); // P = -P
	}

	if (P.isZero() || m.equals(FlexiBigInt.ZERO)) {
	    return H;
	}

	if (m.equals(FlexiBigInt.ONE)) {
	    return P;
	}

	final int l = m.bitLength() - 1;
	for (int i = l; i >= 0; i--) {
	    if (m.testBit(i)) {
		H.multiplyThisBy2();
		H = P.add(H);
	    } else {
		H.multiplyThisBy2();
	    }
	}
	return H.getAffin();
    }

    /**
     * Square and multiply evaluation <i>with</i> recoding. This is also known
     * by <i>binary method</i> or <i>fast exponentiation</i>. This method
     * returns <tt>m*p</tt>. This variant requires a recoding that uses only
     * odd digits. The corresponding positive powers must be stored in
     * <tt>P</tt>.
     * 
     * @param N
     *                the recoded scalar as int-array
     * @param P
     *                array with the precomputed positive odd powers.<br>
     *                <tt>P[i] = (2i + 1)*p</tt>
     * 
     * @return <tt>m*p</tt>
     */
    public static Point eval_SquareMultiply(int[] N, Point[] P) {
	Point r = createZeroPoint(P[0], P[0], P[0].getE());
	int l = N.length - 1;
	for (int i = l; i >= 0; i--) {
	    r.multiplyThisBy2();
	    int index = N[i];
	    if (index > 0) {
		r.addToThis(P[(index - 1) >> 1]);
	    } else if (index < 0) {
		r.subtractFromThis(P[(-index - 1) >> 1]);
	    }
	}
	return r.getAffin();
    }

    /**
     * Square and multiply evaluation with recoding. This is also known by
     * <i>binary method</i> or <i>fast exponentiation</i>. This method returns
     * <tt>m*p</tt>. This variant requires a recoding that uses only positive
     * digits. It needs to have <i>all positive</i> powers of p stored in
     * <tt>P</tt>.
     * 
     * @param N
     *                the recoded scalar as int-array
     * @param P
     *                array with the precomputed positive powers.<br>
     *                <tt>P[i] = (i + 1)*p</tt>
     * @return <tt>m*p</tt>
     */
    public static Point eval_SquareMultiply_all(int[] N, Point[] P) {
	Point r;
	r = createZeroPoint(P[0], P[0], P[0].getE());
	final int l = N.length - 1;
	for (int i = l; i >= 0; i--) {
	    if (N[i] != 0) {
		r.multiplyThisBy2();
		r = r.add(P[N[i] - 1]);
	    } else {
		r.multiplyThisBy2();
	    }
	}
	return r.getAffin();
    }

    /**
     * <i>Shamir (= simultExpo) evaluation</i> for simultaneous multiplications
     * without recoding. This method returns <tt>e1*P + e2*Q</tt>.
     * 
     * @param P
     *                base point
     * @param Q
     *                base point
     * @param e1
     *                <tt>FlexiBigInt</tt>
     * @param e2
     *                <tt>FlexiBigInt</tt>
     * @return <tt>e1*P + e2*Q</tt>
     */
    public static Point eval_shamir(Point P, Point Q, FlexiBigInt e1,
	    FlexiBigInt e2) {
	int t = (e1.bitLength() >= e2.bitLength()) ? e1.bitLength() : e2
		.bitLength();

	Point G1, G2, G3, r;
	G1 = (Point) P.clone();
	G2 = (Point) Q.clone();
	G3 = P.add(Q); // "Precomputation" G3 = P + Q
	r = createZeroPoint(P, Q, Q.getE());

	for (int i = t - 1; i >= 0; i--) {
	    r.multiplyThisBy2();
	    if (e1.testBit(i) && e2.testBit(i)) {
		r = G3.add(r);
	    }
	    if (e1.testBit(i) && !e2.testBit(i)) {
		r = G1.add(r);
	    }
	    if (!e1.testBit(i) && e2.testBit(i)) {
		r = G2.add(r);
	    }
	}
	return r.getAffin();
    }

    /**
     * <i>Shamir (= simultExpo) evaluation</i> for simultaneous multiplications
     * <i>with</i> recoding. The representations of the scalars must have
     * positive digits.
     * 
     * @param N
     *                2-lined matrix.<br>
     *                line 0 contains the recoded representation of e<sub>1</sub>;<br>
     *                line 1 contains the recoded representation of e<sub>2</sub>.
     * @param P
     *                matrix with the precomputed powers.<br>
     *                <tt>p[i][j] = i*P + j*Q</tt> for
     *                <tt>i,j = 0,1,2,...,2<sup>w</sup>-1</tt> or similar
     * @return <tt>e1*P + e2*Q</tt>
     */
    public static Point eval_shamir_all(int[][] N, Point[][] P) {
	int t = (N[0].length >= N[1].length) ? N[0].length - 1
		: N[1].length - 1;
	Point r = createZeroPoint(P[0][1], P[1][0], P[0][1].getE());

	for (int i = t; i >= 0; i--) {
	    r.multiplyThisBy2();
	    int z1 = 0;
	    int z2 = 0;
	    if (i < N[0].length && N[0][i] != 0) {
		z1 = N[0][i];
	    }
	    if (i < N[1].length && N[1][i] != 0) {
		z2 = N[1][i];
	    }
	    if (i < N[0].length && N[0][i] != 0 || i < N[1].length
		    && N[1][i] != 0) {
		r = r.add(P[z1][z2]);
	    }
	}
	return r.getAffin();
    }

    /**
     * <i>Shamir evaluation</i> with 2 base points (<tt>e0*P<sub>0</sub> + 
     * e1*P<sub>1</sub></tt>).
     * In this method, only the use of representations with odd (positive and
     * negative) digits is supported.
     * 
     * @param N
     *                2-lined matrix.<br>
     *                line i contains the recoded representation of
     *                <tt>e<sub>i</sub></tt>;
     * @param P
     *                matrix with the precomputed powers. Use the
     *                {@link #pre_shamir(Point Q0, Point Q1, int w)  Shamir
     *                precomputation}.
     * @return <tt>e0*P<sub>0</sub> + e1*P<sub>1</sub></tt>
     */
    public static Point eval_shamir(int[][] N, Point[][] P) {
	int t = (N[0].length >= N[1].length) ? N[0].length - 1
		: N[1].length - 1;
	Point r = createZeroPoint(P[0][1], P[1][0], P[0][1].getE());

	for (int i = t; i >= 0; i--) {
	    r.multiplyThisBy2();
	    int z1 = 0;
	    int z2 = 0;
	    if (i < N[0].length && N[0][i] != 0) {
		if (N[0][i] >= 0) {
		    z1 = N[0][i];
		} else if (N[0][i] < 0) {
		    z1 = -N[0][i] + 1;
		}
	    }
	    if (i < N[1].length && N[1][i] != 0) {
		if (N[1][i] >= 0) {
		    z2 = N[1][i];
		} else if (N[1][i] < 0) {
		    z2 = -N[1][i] + 1;
		}
	    }
	    if (i < N[0].length && N[0][i] != 0 || i < N[1].length
		    && N[1][i] != 0) {
		r = r.add(P[z1][z2]);
	    }
	}
	return r.getAffin();
    }

    /**
     * <i>Shamir evaluation</i> with 3 base points (<tt>e0*P<sub>0</sub> + 
     * e1*P<sub>1</sub> + e2*P<sub>2</sub></tt>).
     * In this method, only the use of representations with odd (positive and
     * negative) digits is supported.
     * 
     * @param N
     *                3-lined matrix.<br>
     *                line i contains the recoded representation of
     *                <tt>e<sub>i</sub></tt>;
     * @param P
     *                matrix with the precomputed powers. Use the
     *                {@link #pre_shamir(Point Q0, Point Q1, Point Q2, int w)  Shamir
     *                precomputation}.
     * @return <tt>e0*P<sub>0</sub> + e1*P<sub>1</sub> + e2*P<sub>2</sub></tt>
     */
    public static Point eval_shamir(int[][] N, Point[][][] P) {
	int t = N[0].length - 1;
	for (int i = 1; i < N.length; i++) {
	    t = (N[i].length - 1 > t) ? N[i].length - 1 : t;
	}
	Point r = createZeroPoint(P[0][0][0], P[0][0][0], P[0][0][0].getE());

	for (int i = t; i >= 0; i--) {
	    r.multiplyThisBy2();
	    int z1 = 0;
	    int z2 = 0;
	    int z3 = 0;
	    if (i < N[0].length && N[0][i] != 0) {
		if (N[0][i] >= 0) {
		    z1 = N[0][i];
		} else if (N[0][i] < 0) {
		    z1 = -N[0][i] + 1;
		}
	    }
	    if (i < N[1].length && N[1][i] != 0) {
		if (N[1][i] >= 0) {
		    z2 = N[1][i];
		} else if (N[1][i] < 0) {
		    z2 = -N[1][i] + 1;
		}
	    }
	    if (i < N[2].length && N[2][i] != 0) {
		if (N[2][i] >= 0) {
		    z3 = N[2][i];
		} else if (N[2][i] < 0) {
		    z3 = -N[2][i] + 1;
		}
	    }
	    if (N[0][i] != 0 || N[1][i] != 0 || N[2][i] != 0) {
		r = r.add(P[z1][z2][z3]);
	    }
	}
	return r.getAffin();
    }

    /**
     * <i>Shamir evaluation</i> with 4 base points (<tt>e0*P<sub>0</sub> + 
     * e1*P<sub>1</sub> + e2*P<sub>2</sub> + e3*P<sub>3</sub></tt>).
     * In this method, only the use of representations with odd (positive and
     * negative) digits is supported.
     * 
     * @param N
     *                4-lined matrix.<br>
     *                line i contains the recoded representation of
     *                <tt>e<sub>i</sub></tt>;
     * @param P
     *                matrix with the precomputed powers. Use the
     *                {@link #pre_shamir(Point Q0, Point Q1, Point Q2, Point Q3, int w) 
     *                Shamir precomputation}.
     * @return <tt>e0*P<sub>0</sub> + e1*P<sub>1</sub> + e2*P<sub>2</sub> 
     * 			+ e3*P<sub>3</sub></tt>
     */
    public static Point eval_shamir(int[][] N, Point[][][][] P) {
	int t = N[0].length - 1;
	for (int i = 1; i < N.length; i++) {
	    t = (N[i].length - 1 > t) ? N[i].length - 1 : t;
	}
	Point r = createZeroPoint(P[0][0][0][0], P[0][0][0][0], P[0][0][0][0]
		.getE());

	for (int i = t; i >= 0; i--) {
	    r.multiplyThisBy2();
	    int z1 = 0;
	    int z2 = 0;
	    int z3 = 0;
	    int z4 = 0;
	    if (i < N[0].length && N[0][i] != 0) {
		if (N[0][i] >= 0) {
		    z1 = N[0][i];
		} else if (N[0][i] < 0) {
		    z1 = -N[0][i] + 1;
		}
	    }
	    if (i < N[1].length && N[1][i] != 0) {
		if (N[1][i] >= 0) {
		    z2 = N[1][i];
		} else if (N[1][i] < 0) {
		    z2 = -N[1][i] + 1;
		}
	    }
	    if (i < N[2].length && N[2][i] != 0) {
		if (N[2][i] >= 0) {
		    z3 = N[2][i];
		} else if (N[2][i] < 0) {
		    z3 = -N[2][i] + 1;
		}
	    }
	    if (i < N[3].length && N[3][i] != 0) {
		if (N[3][i] >= 0) {
		    z4 = N[3][i];
		} else if (N[3][i] < 0) {
		    z4 = -N[3][i] + 1;
		}
	    }
	    if (N[0][i] != 0 || N[1][i] != 0 || N[2][i] != 0 || N[3][i] != 0) {
		r = r.add(P[z1][z2][z3][z4]);
	    }
	}
	return r.getAffin();
    }

    /**
     * <i>Interleave evaluation</i> for <i>n-time simultaneous</i>
     * multiplications <i>with</i> recoding
     * 
     * @param N
     *                matrix with the receoded representations.<br>
     *                Line i contains the wNaf-representation of
     *                <tt>e<sub>i</sub></tt>.
     * @param P
     *                point matrix with the precomputed points.<br>
     *                The odd powers of <tt>P<sub>i</sub></tt> are stored in
     *                line i.
     * @return <tt>e<sub>0</sub>*P<sub>0</sub> + e<sub>1</sub>*P<sub>1</sub> 
     * 			+ ... + e<sub>n-1</sub>*P<sub>n-1</sub></tt>
     */
    public static Point eval_interleaving(int[][] N, Point[][] P) {
	Point r = createZeroPoint(P[0][0], P[0][0], P[0][0].getE());
	int t = N[0].length - 1;
	for (int i = 1; i < N.length; i++) {
	    t = (N[i].length - 1 > t) ? N[i].length - 1 : t;
	}

	for (int j = t; j >= 0; j--) {
	    r.multiplyThisBy2();
	    for (int i = 0; i < N.length; i++) {
		if (j < N[i].length) {
		    if (N[i][j] > 0) {
			r = P[i][(N[i][j] - 1) >> 1].add(r);
		    } else if (N[i][j] < 0) {
			r = r.subtract(P[i][(-N[i][j] - 1) >> 1]);
		    }
		}
	    }
	}
	return r;
    }

    // ////////////////////////////////////////////////////////////////////
    // creators
    // ////////////////////////////////////////////////////////////////////

    /**
     * @param type1
     * @param type2
     * @param curve
     * @return
     */
    private static Point createZeroPoint(Object type1, Object type2,
	    Object curve) {
	if (type1 instanceof PointGFP && type2 instanceof PointGFP
		&& curve instanceof EllipticCurveGFP) {
	    return new PointGFP((EllipticCurveGFP) curve);
	} else if (type1 instanceof PointGF2n && type2 instanceof PointGF2n
		&& curve instanceof EllipticCurveGF2n) {
	    return new PointGF2n((EllipticCurveGF2n) curve);
	}
	return null;
    }

    /**
     * @param cols
     * @param rows
     * @return
     */
    private static Point[][] createPointMatrix(Object type1, Object type2,
	    int cols, int rows) {
	if (type1 instanceof PointGFP && type2 instanceof PointGFP) {
	    return new PointGFP[cols][rows];
	} else if (type1 instanceof PointGF2n && type2 instanceof PointGF2n) {
	    return new PointGF2n[cols][rows];
	}
	return null;
    }

    private static GF2nElement createGF2nOneElement(GF2nField gf2n) {
	if (gf2n instanceof GF2nONBField) {
	    return GF2nONBElement.ONE((GF2nONBField) gf2n);
	}
	return GF2nPolynomialElement.ONE((GF2nPolynomialField) gf2n);
    }
}
