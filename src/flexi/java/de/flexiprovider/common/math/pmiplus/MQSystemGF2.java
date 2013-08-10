package de.flexiprovider.common.math.pmiplus;

import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.common.math.finitefields.GF2nPolynomialElement;
import de.flexiprovider.common.math.finitefields.GF2nPolynomialField;
import de.flexiprovider.common.math.linearalgebra.GF2Matrix;
import de.flexiprovider.common.util.IntUtils;

/**
 * This class describes some operations with set of polynomials over finite
 * field GF(2) and is used in PMIPlus (also has some specific methods and
 * implementation)
 * <p>
 * For the matrix representation the array of type int[][] is used, thus one
 * element of the array keeps 32 elements of the matrix (from one row and 32
 * columns)
 * 
 * @author Elena Klintsevich
 */

public class MQSystemGF2 {

    /*
     * parameters:
     * 
     */

    private int n;

    private int m;

    private int[][] poly;

    /*
     * -------------------constructors
     */
    /**
     * create 1 polynomial in GF(2)[]
     */
    public MQSystemGF2() {
	this.n = 0;
	this.m = 1;
	this.poly = new int[1][1];
	poly[0][0] = 1;
    }

    /**
     * create m polynomials in GF(2)[x_1,...,x_n]
     */
    public MQSystemGF2(int n, int m) {
	if (n < 0) {
	    throw new IllegalArgumentException(
		    " Error: number of variables is less than 0");
	}
	if (m < 0) {
	    throw new IllegalArgumentException(
		    " Error: number of polynomials is less than 0");
	}

	this.m = m;
	this.n = n;

	/*
	 * number of terms with degree two is n(n-1)/2, with degree one n, and
	 * with degree zero 1. Thus n(n+1)/2+1
	 */
	int nn = ((n * (n + 1)) >>> 1) + 1;

	/*
	 * Since each element of array keeps 32 coefficients of polynomial
	 * system, number of elements is equal to ceil(m/32)
	 */
	int mm = (m + 31) >> 5;

	poly = new int[nn][mm];
    }

    /**
     * create the set of polynomials with coefficients from array p
     */
    public MQSystemGF2(int n, int m, int[][] p) {
	if (n < 0) {
	    throw new IllegalArgumentException(
		    " Error: number of variables is less than 0");
	}
	if (m < 0) {
	    throw new IllegalArgumentException(
		    " Error: number of polynomials is less than 0");
	}

	this.m = m;
	this.n = n;

	/*
	 * number of terms with degree two is n(n-1)/2, with degree one n, and
	 * with degree zero 1. Thus n(n+1)/2+1
	 */
	int nn = ((n * (n + 1)) >>> 1) + 1;

	/*
	 * Since each element of array keeps 32 coefficients of polynomial
	 * system, number of elements is equal to ceil(m/32)
	 */
	int mm = (m + 31) >> 5;

	if (nn != p.length) {
	    throw new IllegalArgumentException(" Error: array p is not correct");
	}

	poly = new int[nn][mm];

	for (int i = 0; i < nn; i++) {
	    if (mm != p[i].length) {
		throw new IllegalArgumentException(
			" Error: array p is not correct");
	    }
	    System.arraycopy(p[i], 0, poly[i], 0, mm);

	}

	int r = m & 0x1f;
	if (r == 0) {
	    r = 0xffffffff;
	} else {
	    r = (1 << r) - 1;
	}

	mm--;
	for (int i = 0; i < nn; i++) {
	    poly[i][mm] &= r;
	}

    }

    /**
     * @return the number of variable
     */
    public final int getN() {
	return this.n;
    }

    /**
     * @return the number of polynomials
     */
    public final int getM() {
	return this.m;
    }

    /**
     * @return the MQ polynomial system
     */
    public final int[][] getPoly() {
	return poly;
    }

    /**
     * The method creates random set of m quadratic polynomial in n variable
     * 
     * @param n -
     *                the number of variable
     * @param m -
     *                the number of polynomials
     */
    public final void createRndMQS(int n, int m) {
	SecureRandom sr = Registry.getSecureRandom();
	this.createRndMQS(n, m, sr);
    }

    /**
     * The method creates random set of m quadratic polynomial in n variable
     * 
     * @param n -
     *                the number of variable
     * @param m -
     *                the number of polynomials
     * @param sr -
     *                PRNG
     */
    public final void createRndMQS(int n, int m, SecureRandom sr) {
	if (n < 0) {
	    throw new IllegalArgumentException(
		    " Error: number of variables is less than 0");
	}
	if (m < 0) {
	    throw new IllegalArgumentException(
		    " Error: number of polynomials is less than 0");
	}

	this.m = m;
	this.n = n;

	/*
	 * number of terms with degree two is n(n-1)/2, with degree one n, and
	 * with degree zero 1. Thus n(n+1)/2+1
	 */
	int nn = ((n * (n + 1)) >>> 1) + 1;

	/*
	 * Since each element of array keeps 32 coefficients of polynomial
	 * system, number of elements is equal to ceil(m/32)
	 */
	int mm = (m + 31) >>> 5;
	poly = new int[nn][mm];

	int r = m & 0x1f;
	if (r == 0) {
	    r = 0xffffffff;
	} else {
	    r = (1 << r) - 1;
	}
	mm--;
	for (int i = 0; i < nn; i++) {
	    for (int j = 0; j < mm; j++) {
		poly[i][j] = sr.nextInt();
	    }
	    poly[i][mm] = sr.nextInt() & r;
	}
    }

    /**
     * compute [f1(a1,...,an),...,fm(a1,...,an)], where {f_i} is this system,
     * and A = (a1,...,an) is a point in GF(2)^n
     * 
     * @param point
     *                bytes representation of A
     * @return int representation of the value of this system on point A
     */
    public final int[] findValueOnPointX(byte[] point) {
	if ((n < ((point.length << 3) - 7)) || (n > (point.length << 3))) {
	    throw new IllegalArgumentException(
		    " Error: point is not from GF(2)^" + n);
	}

	int[] res = IntUtils.clone(poly[poly.length - 1]);

	int count = 0;
	int ri, qi;
	byte ei;
	for (int i = 0; i < n; i++) {
	    // find q and r such that i = 8q+i
	    ri = i & 7;
	    qi = i >>> 3;
	    ei = (byte) ((point[qi] >>> ri) & 1);
	    if (ei == 0) {
		count += n - i;
	    } else {
		for (int j = 0; j < res.length; j++) {
		    res[j] ^= poly[count][j];
		}
		count++;

		for (int ii = i + 1; ii < n; ii++) {
		    qi = ii >>> 3;
		    ri = ii & 7;
		    ei = (byte) ((point[qi] >>> ri) & 1);
		    if (ei == 1) {
			for (int j = 0; j < res.length; j++) {
			    res[j] ^= poly[count][j];
			}
		    }

		    count++;
		}
	    } // end else
	} // end for_i

	return res;
    }

    /**
     * compute F(MX+V), where M is an nxk-matrix over GF(2) V is an n-vector of
     * constants, and F is this systems, i.e., replace old variables by
     * affine-linear combinations of new ones. result is a new system of n
     * polynomial
     * 
     * @param vector
     * @param mtr
     *                matrix over GF2
     * @return new polynomial system
     */
    public final MQSystemGF2 compositionWithLinMapL(int[] vector, GF2Matrix mtr) {
	if ((n < ((vector.length << 5) - 31)) || (n > (vector.length << 5))) {
	    throw new IllegalArgumentException(
		    " Error: vector is not from GF(2)^" + n);
	}

	if (this.n != mtr.getNumRows()) {
	    throw new IllegalArgumentException(" Error: matrix is not " + n
		    + " x k");
	}

	int k = mtr.getNumColumns(); // k -the number of new variables
	int kk = ((k * (k + 1)) >> 1) + 1; // the number of terms
	// find q and r such that k = 32q+r
	int qk = k >>> 5;
	int rk = k & 0x1f;
	rk = 1 << rk;

	int[][] res = new int[kk][this.poly[0].length];

	int[][] a = mtr.getIntArray();

	// help variables
	int q, r, e, b, ind, ind0;
	int count = 0;
	byte[] help, help0, help1;
	byte hb0, hb1;

	// take variable step by step
	for (int i = 0; i < this.n; i++) {
	    /*
	     * replace linear term x_i by (A_ij y_j + v_i) for x_i variable
	     * exists n-i terms
	     */
	    ind = 0;
	    ind0 = 0;
	    help0 = new byte[k];

	    /*
	     * take element (type int)of row of matrix a, recall that this
	     * element keeps 32 coefficients
	     */
	    for (int j = 0; j < qk; j++) {
		b = 1;
		while (b != 0) {
		    e = a[i][j] & b;
		    if (e != 0) {
			help0[ind0] = 1;
			for (int ii = 0; ii < res[ind].length; ii++) {
			    res[ind][ii] ^= poly[count][ii];
			}
		    }
		    b <<= 1;
		    ind += k - ind0;
		    ind0++;
		} // end_while
	    } // for_j
	    b = 1;
	    while (b != rk) {
		e = a[i][qk] & b;
		if (e != 0) {
		    help0[ind0] = 1;
		    for (int ii = 0; ii < res[ind].length; ii++) {
			res[ind][ii] ^= poly[count][ii];
		    }
		}
		b <<= 1;
		ind += k - ind0;
		ind0++;
	    } // end_while

	    // find v_i
	    q = i >>> 5;
	    r = i & 0x1f;
	    hb0 = (byte) ((vector[q] >>> r) & 1);
	    if (hb0 == 1) {
		for (int ii = 0; ii < res[ind].length; ii++) {
		    res[ind][ii] ^= poly[count][ii];
		}
	    }

	    count++;

	    /*
	     * replace variables in quadratic terms x_i x_j
	     */
	    for (int j = i + 1; j < this.n; j++) {
		/*
		 * rewrite A_j in bytes form
		 */
		ind0 = 0;
		help1 = new byte[k];
		for (int jj = 0; jj < qk; jj++) {
		    b = 1;
		    while (b != 0) {
			e = a[j][jj] & b;
			if (e != 0) {
			    help1[ind0] = 1;
			}
			b <<= 1;
			ind0++;
		    } // end_while
		} // for_j
		b = 1;
		while (b != rk) {
		    e = a[j][qk] & b;
		    if (e != 0) {
			help1[ind0] = 1;
		    }
		    b <<= 1;
		    ind0++;
		} // end_while

		// find v_j
		q = j >>> 5;
		r = j & 0x1f;
		hb1 = (byte) ((vector[q] >>> r) & 1);

		// find indeces of columns with x_i x_j
		help = new byte[kk];
		ind = 0;
		for (int ii = 0; ii < k; ii++) {
		    if (help0[ii] == 0) {
			ind += k - ii;
		    } else {
			help[ind] ^= hb1;
			for (int jj = ii; jj < k; jj++) {
			    help[ind] ^= help1[jj];
			    ind++;
			}
		    }
		}
		ind = 0;
		for (int ii = 0; ii < k; ii++) {
		    if (help1[ii] == 0) {
			ind += k - ii;
		    } else {
			help[ind] ^= hb0;
			ind++;
			for (int jj = ii + 1; jj < k; jj++) {
			    help[ind] ^= help0[jj];
			    ind++;
			}
		    }
		}
		help[kk - 1] ^= hb0 & hb1;

		for (int ii = 0; ii < kk; ii++) {
		    if (help[ii] == 1) {
			for (int jj = 0; jj < res[ii].length; jj++) {
			    res[ii][jj] ^= poly[count][jj];
			}
		    }
		}

		count++;
	    } // for_j
	} // for_i

	ind = kk - 1;
	for (int i = 0; i < res[ind].length; i++) {
	    res[ind][i] ^= poly[count][i];
	}

	return new MQSystemGF2(k, m, res);
    }

    /**
     * compute MF+V, where M is an kxm-matrix over GF(2) V is an k-vector of
     * constants, and F is this systems. result is a new system of k polynomial
     * 
     * @param vector
     * @param mtr
     *                matrix over GF2
     * @return new polynomial system
     */
    public final MQSystemGF2 compositionWithLinMapR(int[] vector, GF2Matrix mtr) {
	int k = mtr.getNumRows();

	if ((k < ((vector.length << 5) - 31)) || (k > (vector.length << 5))) {
	    throw new IllegalArgumentException(
		    " Error: vector is not from GF(2)^" + k);
	}

	if (this.m != mtr.getNumColumns()) {
	    throw new IllegalArgumentException(" Error: matrix is not k x" + m);
	}

	int[][] res = new int[this.poly.length][vector.length];

	int[][] a = mtr.getIntArray();
	int d = this.poly[0].length - 1;
	int r0 = this.m & 0x1f;
	if (r0 == 0) {
	    r0 = 0xffffffff;
	} else {
	    r0 = (1 << r0) - 1;
	}

	int q, r, e, b;

	for (int i = 0; i < res.length; i++) {
	    for (int j = 0; j < k; j++) {
		q = j >>> 5;
		r = j & 0x1f;
		b = 0;
		for (int ii = 0; ii < d; ii++) {
		    b ^= poly[i][ii] & a[j][ii];
		}
		b ^= (poly[i][d] & a[j][d]) & r0;

		e = b & 1;
		for (int ii = 1; ii < 32; ii++) {
		    e ^= (b >>> ii) & 1;
		}

		res[i][q] ^= e << r;
	    }
	}

	d = res.length - 1;
	b = res[d].length - 1;
	r0 = k & 0x1f;
	if (r0 == 0) {
	    r0 = 0xffffffff;
	} else {
	    r0 = (1 << r0) - 1;
	}

	for (int i = 0; i <= b; i++) {
	    res[d][i] ^= vector[i];
	}
	res[d][b] &= r0;

	return new MQSystemGF2(n, k, res);
    }

    /**
     * Compute the quadratic polynomial system over GF(2) describing the map of
     * GF(2^n) to GF(2^n) f: X ---> X^(1+2^d), where d is given. Finally this
     * polynomial system is replaced by result.
     * 
     * @param field
     *                finite field GF(2^n)
     * @param d
     *                non-negative integer
     */
    public final void createSystemFromXd(GF2nPolynomialField field, int d) {
	if (d < 0) {
	    throw new IllegalArgumentException(" Error: d < 0");
	}

	this.n = field.getDegree();
	this.m = this.n;

	/*
	 * first step. compute linear system for the map X^(2^d)
	 */
	// al is an element of finite field GF(2^n) such that
	// 1,al,al^2,al^3,...,al^(n-1) is basis of this field (as vector space
	// over GF2)
	int[] one = { 1 };
	int[] alpha = { 2 };
	GF2nPolynomialElement al = new GF2nPolynomialElement(field, alpha);
	GF2nPolynomialElement[] lin = new GF2nPolynomialElement[n];
	lin[0] = new GF2nPolynomialElement(field, one);
	for (int i = 1; i < n; i++) {
	    lin[i] = al.power(i);
	    // compute (al^i)^(2^d)
	    for (int j = 0; j < d; j++) {
		lin[i] = lin[i].squareMatrix();
		// lin[i] = lin[i].squarePreCalc();//one of both
	    }
	}
	// !!!!!!!!!!to do

    }

    /**
     * compute {f1+g1,..., fm+gm}, where {fi} is this system and {gi} is given
     * 
     * @param mqs
     *                is system of polynomials {gi}
     * @return new system {f_i+g_i}
     */
    public final MQSystemGF2 addPolynomials(MQSystemGF2 mqs) {
	if ((this.n != mqs.n) || (this.m != mqs.m)) {
	    throw new IllegalArgumentException(" the systems cannot be added ");
	}

	int[][] res = new int[this.poly.length][this.poly[0].length];

	for (int i = 0; i < res.length; i++) {
	    for (int j = 0; j < res[0].length; j++) {
		res[i][j] = this.poly[i][j] ^ mqs.poly[i][j];
	    }
	}

	return new MQSystemGF2(n, m, res);
    }

    /**
     * return new system {f1,...,fm,g1,...,gk}, where {fi} is this system and
     * {gi} is given
     * 
     * @param mqs
     *                system of polynomials {gi}
     * @return new system {f_i, g_j}
     */
    public final MQSystemGF2 twoSystemsToOne(MQSystemGF2 mqs) {
	if (this.n != mqs.n) {
	    throw new IllegalArgumentException(
		    " Errors: the systems have different number of variables");
	}

	if (mqs.m == 0) {
	    return this;
	}

	int rm = this.m + mqs.m;
	int mm = (rm + 31) >>> 5;
	int r = this.m & 0x1f;
	int r0 = 32 - r;
	int[][] res = new int[this.poly.length][mm];
	int ind;
	int[] help = new int[mqs.poly[0].length + 1];

	for (int i = 0; i < res.length; i++) {
	    System.arraycopy(this.poly[i], 0, res[i], 0, this.poly[i].length);

	    help[0] = mqs.poly[i][0] << r;
	    for (int j = 1; j < mqs.poly[i].length; j++) {
		help[j] = (mqs.poly[i][j] << r) ^ (mqs.poly[i][j - 1] >>> r0);
	    }
	    help[mqs.poly[i].length] = mqs.poly[i][mqs.poly[i].length - 1] >>> r0;

	    res[i][this.poly[i].length - 1] ^= help[0];
	    ind = 0;
	    for (int j = this.poly[i].length; j < mm; j++) {
		ind++;
		res[i][j] = help[ind];
	    }
	}

	return new MQSystemGF2(this.n, rm, res);
    }

    /*
     * --------------------- help methods
     */

    /**
     * print the set of polynomials
     */
    public final void show() {
	System.out.println(" ----- ");
	int r = m & 0x1f;
	int mm = poly[0].length - 1;

	for (int i = 0; i < n; i++) {
	    System.out.print("  x" + i + " ");
	    for (int j = i + 1; j < n; j++) {
		System.out.print(" x" + i + "x" + j);
	    }
	}
	System.out.println("  1");

	for (int i = 0; i < mm; i++) {
	    for (int ii = 0; ii < 32; ii++) {
		for (int j = 0; j < poly.length; j++) {
		    System.out.print("  " + ((poly[j][i] >> ii) & 1) + "  ");
		}
		System.out.println(";");
	    }
	}

	for (int ii = 0; ii < r; ii++) {
	    for (int j = 0; j < poly.length; j++) {
		System.out.print("  " + ((poly[j][mm] >> ii) & 1) + "  ");
	    }
	    System.out.println(";");
	}

	System.out.println(" ----- ");
    }
}
