package de.flexiprovider.common.math.quadraticfields;

import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.exceptions.InvalidParameterException;
import de.flexiprovider.common.exceptions.NoQuadraticResidueException;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.math.IntegerFunctions;

public class IQClassGroup {
    /*
     * Constants
     */

    private static final int PRIME_CERTAINTY = 15;

    private static final int RANDOM_PRIME_POWER_IDEAL_EXPONENT = 5;

    private static final int RANDOM_PRIME_POWER_IDEAL_BITLENGTH = 70;

    private static final int RANDOM_IDEAL_ITERATIONS = 4;

    /*
     * Member variables
     */

    private SecureRandom prng;

    private FlexiBigInt discriminant;

    private final boolean reduceFlag = true;

    /**
     * Constructor.
     * 
     * @param discriminant
     *                discriminant of class group
     * @param prng
     *                instance of a pseudo-random number generator
     */
    public IQClassGroup(FlexiBigInt discriminant, SecureRandom prng) {
	this.prng = (prng == null) ? Registry.getSecureRandom() : prng;
	this.discriminant = discriminant;
    }

    /**
     * Constructor.
     * 
     * @param discriminant
     *                discriminant of class group
     */
    public IQClassGroup(FlexiBigInt discriminant) {
	this(discriminant, null);
    }

    /**
     * Constructor.
     * 
     * @param bits
     *                length of the binary expansion of the discriminant
     * @param primeDiscriminant
     *                flag to indicate whether the absolute value of the
     *                discriminant has to be a prime or not
     * @param prng
     *                instance of pseudo-random number generator
     */
    public IQClassGroup(int bits, boolean primeDiscriminant, SecureRandom prng) {
	this.prng = (prng == null) ? Registry.getSecureRandom() : prng;

	do {
	    discriminant = new FlexiBigInt(bits, this.prng).or(FlexiBigInt
		    .valueOf(3));
	    discriminant = discriminant.setBit(bits - 1);

	    if (primeDiscriminant) {
		while (!discriminant.isProbablePrime(PRIME_CERTAINTY)) {
		    discriminant = discriminant.add(FlexiBigInt.valueOf(4));
		}
	    }
	} while (discriminant.bitLength() != bits);

	discriminant = discriminant.negate();
    }

    /**
     * Constructor.
     * 
     * @param bits
     *                length of the binary expension of the discriminant
     * @param primeDiscriminant
     *                flag to indicate whether the absolute value of the
     *                discriminant has to be a prime or not
     */
    public IQClassGroup(int bits, boolean primeDiscriminant) {
	this(bits, primeDiscriminant, null);
    }

    /**
     * Query discriminant of an <tt>IQClassGroup</tt> object.
     * 
     * @return discriminant of class group
     */
    public FlexiBigInt getDiscriminant() {
	return discriminant;
    }

    // /////////////////////////////////////////////////////////////////////////

    private FlexiBigInt sqrtDeltaThirds = null;

    private FlexiBigInt sqrtDeltaHalves = null;

    /**
     * Check whether we have a reduced ideal already.
     * 
     * @return <tt>true</tt> if ideal is reduced, <tt>false</tt> otherwise.
     */
    public boolean isReduced(QuadraticIdeal I) {
	if (sqrtDeltaThirds == null) {
	    sqrtDeltaThirds = IntegerFunctions.squareRoot(discriminant.abs()
		    .divide(FlexiBigInt.valueOf(3)));
	}
	if (sqrtDeltaHalves == null) {
	    // divide by two done for reasons of clarity. speed impact compared
	    // to bit
	    // shifting is minimal.
	    sqrtDeltaHalves = IntegerFunctions.squareRoot(discriminant.abs()
		    .divide(FlexiBigInt.valueOf(2)));
	}

	if (I.a.signum() <= 0 || I.a.compareTo(sqrtDeltaThirds) > 0) {
	    return false;
	}
	if (I.b.compareTo(I.a.negate()) < 0 || I.b.compareTo(I.a) > 0) {
	    return false;
	}
	if (I.a.compareTo(sqrtDeltaHalves) <= 0) {
	    return true;
	}

	// divide by four done for reasons of clarity. speed impact compared to
	// bit
	// shifting is minimal.
	FlexiBigInt c = I.b.multiply(I.b).subtract(discriminant);
	c = c.divide(I.a).divide(FlexiBigInt.valueOf(4));

	if (I.a.compareTo(c) > 0) {
	    return false;
	}
	if (I.a.compareTo(c) == 0 && I.b.signum() < 0) {
	    return false;
	}

	return true;
    }

    /**
     * <tt>discriminant = b^2 - 4ac</tt>, thus
     * <tt>(b^2 - discriminant) mod 4a</tt> better be zero for <tt>c</tt> to
     * be an integer.
     * 
     * @return the result of the test <tt>(b^2 - discriminant) mod 4a == 0</tt>
     */
    public boolean isValid(QuadraticIdeal I) {
	FlexiBigInt tmp = I.b.multiply(I.b).subtract(discriminant);

	return tmp.remainder(I.a.multiply(FlexiBigInt.valueOf(4))).signum() == 0;
    }

    /**
     * Reduce a quadratic ideal.
     */
    private QuadraticIdeal reduce(FlexiBigInt a, FlexiBigInt b) {
	int sign = 1;
	FlexiBigInt c, t1, t;
	FlexiBigInt q, r;
	FlexiBigInt[] qr;

	// check whether ideal is normal
	if ((a.compareTo(b) < 0) || (a.negate().compareTo(b) >= 0)) {
	    // we need to normalize
	    // b = a - ((a - b) mod (2a))
	    b = a.subtract(a.subtract(b).mod(a.shiftLeft(1)));
	}
	if (b.signum() < 0) {
	    b = b.abs();
	    sign = -1;
	}

	// compute c
	// c = (b^2 - Delta) / (4*a)
	c = b.multiply(b).subtract(discriminant);

	if (c.remainder(a.shiftLeft(2)).signum() != 0) {
	    throw new InvalidParameterException("invalid ideal");
	}

	c = c.divide(a.shiftLeft(2));

	while (a.compareTo(c) > 0) {
	    // swap a and c
	    t = a;
	    a = c;

	    // t1 = 2 * a
	    t1 = a.shiftLeft(1);

	    if ((b.bitLength() - t1.bitLength()) > 2) {
		qr = b.divideAndRemainder(t1);
		q = qr[0];
		r = qr[1];
	    } else {
		int q_int;
		r = b;

		for (q_int = 0; r.compareTo(t1) > 0;) {
		    r = r.subtract(t1);
		    q_int++;
		}
		q = FlexiBigInt.valueOf(q_int);
	    }

	    // c = t - q * (r + b) >> 1
	    c = t.subtract(q.multiply(r.add(b)).shiftRight(1));

	    // a < r
	    if (a.compareTo(r) < 0) {
		// b = 2 * a - r
		b = t1.subtract(r);
		// c' = c + a - r
		c = c.add(a).subtract(r);
	    } else {
		/* a >= r */
		b = r;
		sign = -sign;
	    }
	}

	if (sign < 0) {
	    b = b.negate();
	}

	// check whether ideal is normal
	if ((a.compareTo(b) < 0) || (a.negate().compareTo(b) >= 0)) {
	    // we need to normalize
	    // b = a - ((a - b) mod (2a))
	    b = a.subtract(a.subtract(b).remainder(a.shiftLeft(1)));
	}

	if (a.equals(c) && b.signum() < 0) {
	    b = b.negate();
	}

	return new QuadraticIdeal(a, b);
    }

    /**
     * Reduce a quadratic ideal of the class group.
     * 
     * @param I
     *                ideal to be reduced
     * @return reduced ideal equivalent to I
     */
    public QuadraticIdeal reduce(QuadraticIdeal I) {
	return reduce(I.a, I.b);
    }

    /**
     * Invert a quadratic ideal of the class group.
     * 
     * @return the inverse ideal
     */
    public QuadraticIdeal invert(QuadraticIdeal I) {
	return new QuadraticIdeal(I.a, I.b.negate());
    }

    /**
     * Multiply two quadratic ideals of the class group.
     * 
     * @return the product of the two ideals
     */
    public QuadraticIdeal multiply(FlexiBigInt a1, FlexiBigInt b1,
	    FlexiBigInt a2, FlexiBigInt b2) {
	FlexiBigInt[] temp = new FlexiBigInt[3];
	FlexiBigInt t1, tb;
	FlexiBigInt d1, d2, v, w;
	FlexiBigInt a3, b3;

	// d1 = gcd(abs(a1),abs(a2)) = v * a1 + w * a2
	temp = IntegerFunctions.extgcd(a1, a2);
	d1 = temp[0];
	v = temp[1];
	w = temp[2];

	// tb = a1 * v * (b2 - b1)
	tb = a1.multiply(v).multiply(b2.subtract(b1));

	// a3 = a1 * a2
	a3 = a1.multiply(a2);

	// gcd(a1, a2) ?= 1
	if (d1.compareTo(FlexiBigInt.ONE) != 0) { // gcd(a1,a2) != 1
	    // t1 = (b1 + b2) >> 1
	    t1 = b1.add(b2).shiftRight(1);
	    // d2 = gcd(abs(d1),abs(t1)) = v * d1 + w * t1
	    temp = IntegerFunctions.extgcd(d1, t1);
	    d2 = temp[0];
	    v = temp[1];
	    w = temp[2];
	    // t1 = (w * ((Delta - b1^2) >> 1) + v * tb) / d2
	    t1 = discriminant.subtract(b1.multiply(b1)).multiply(w);
	    tb = t1.shiftRight(1).add(v.multiply(tb)).divide(d2);
	    // a3 = a3 / (d2^2)
	    a3 = a3.divide(d2.multiply(d2));
	}

	// b3 = (b1 + tb) mod (2 * a3)
	b3 = b1.add(tb).mod(a3.shiftLeft(1));

	if (reduceFlag) {
	    return reduce(a3, b3);
	}
	return new QuadraticIdeal(a3, b3);
    }

    /**
     * Multiply two quadratic ideals.
     * 
     * @return the product of the two ideals
     */
    public QuadraticIdeal multiply(QuadraticIdeal I1, QuadraticIdeal I2) {
	return multiply(I1.a, I1.b, I2.a, I2.b);
    }

    /**
     * Divide a quadratic ideal by another.
     * 
     * @param I1
     *                the first ideal (dividend)
     * @param I2
     *                the second ideal (divisor)
     * 
     * @return the remainder of the division
     */
    public QuadraticIdeal divide(QuadraticIdeal I1, QuadraticIdeal I2) {
	return multiply(I1.a, I1.b, I2.a, I2.b.negate());
    }

    /**
     * Square a quadratic ideal.
     * 
     * @return the squared ideal
     */
    public QuadraticIdeal square(FlexiBigInt a, FlexiBigInt b) {
	FlexiBigInt[] temp = new FlexiBigInt[3];
	FlexiBigInt t1;
	FlexiBigInt d1;
	FlexiBigInt a3, b3;

	// d1 = gcd(abs(a),abs(b)) = v * a + w * b

	temp = IntegerFunctions.extgcd(a, b);
	d1 = temp[0];
	// FlexiBigInt v = temp[1];
	FlexiBigInt w = temp[2];

	// a3 = (a / d1)^2
	a3 = a.divide(d1);
	a3 = a3.multiply(a3);

	// t1 = (Delta - b^2) / (2 * d1) * w + b
	t1 = discriminant.subtract(b.multiply(b)).divide(d1.shiftLeft(1));
	t1 = t1.multiply(w).add(b);

	b3 = t1.mod(a3.shiftLeft(1));

	if (reduceFlag) {
	    return reduce(a3, b3);
	}
	return new QuadraticIdeal(a3, b3);
    }

    /**
     * Square a quadratic ideal.
     * 
     * @return the sqared ideal
     */
    public QuadraticIdeal square(QuadraticIdeal I) {
	return square(I.a, I.b);
    }

    /**
     * @return the neutral element of the class group
     */
    public QuadraticIdeal one() {
	return new QuadraticIdeal(1, discriminant.testBit(0) ? 1 : 0);
    }

    /**
     * Check whether the given ideal is the neutral element of the class group.
     * 
     * @param I
     *                the ideal
     * @return <tt>true</tt> if <tt>I</tt> is the neutral element of the
     *         class group, <tt>false</tt> otherwise
     */
    public boolean isOne(QuadraticIdeal I) {
	return I.a.equals(FlexiBigInt.ONE)
		&& !(discriminant.testBit(0) ^ I.b.equals(FlexiBigInt.ONE));
    }

    /**
     * Exponentiate a quadratic ideal (uses signed-digit exponent recoding).
     * 
     * @param I
     *                the ideal
     * @param n
     *                the exponent
     * @return <tt>I<sup>n</sup></tt>
     */
    public QuadraticIdeal power(QuadraticIdeal I, FlexiBigInt n) {
	QuadraticIdeal T, T2;
	int c, cn, d, e, en, i, t;
	int sign;

	T = one();

	// check whether sign of exponent is negative
	if (n.signum() < 0) {
	    n = n.abs();
	    sign = -1;
	} else {
	    sign = 1;
	}

	t = n.bitLength();
	c = 0;
	e = n.testBit(0) ? 1 : 0;
	T2 = I;

	for (i = 0; i <= t; i++) {
	    en = n.testBit(i + 1) ? 1 : 0;
	    cn = (e + en + c) >> 1;
	    d = e + c - 2 * cn;

	    if (d > 0) {
		T = multiply(T, T2);
	    } else if (d < 0) {
		T = divide(T, T2);
	    }

	    e = en;
	    c = cn;
	    T2 = square(T2);
	}

	return sign < 0 ? invert(T) : T;
    }

    /**
     * Exponentiate a quadratic ideal (uses signed-digit exponent recoding) This
     * assumes we have precomputed an array of powers of the ideal (see
     * Gordon-Brickell precomputation).
     * 
     * @param powI
     *                the array of precomputed ideals (first element is base)
     * @param n
     *                the exponent
     * @return <tt>powI[0]<sup>n</sup></tt>
     */
    public QuadraticIdeal power(QuadraticIdeal[] powI, FlexiBigInt n) {
	QuadraticIdeal T;
	int c, cn, d, e, en, i, t;
	int sign;

	T = one();

	// check whether sign of exponent is negative
	if (n.signum() < 0) {
	    n = n.abs();
	    sign = -1;
	} else {
	    sign = 1;
	}

	t = n.bitLength();
	c = 0;
	e = n.testBit(0) ? 1 : 0;

	for (i = 0; i <= t; i++) {
	    en = n.testBit(i + 1) ? 1 : 0;
	    cn = (e + en + c) >> 1;
	    d = e + c - 2 * cn;

	    if (d > 0) {
		T = multiply(T, powI[i]);
	    } else if (d < 0) {
		T = divide(T, powI[i]);
	    }

	    e = en;
	    c = cn;
	}

	return (sign < 0) ? invert(T) : T;
    }

    /**
     * Generate precomputed values for fast exponentation using the Gordon
     * Brickell method.
     * 
     * @param I
     *                the ideal
     * @param n
     *                the number of ideals to precompute
     * @return the array
     *         <tt>[I, I<sup>2<sup>1</sup></sup>, ..., I<sup>2<sup>n-1</sup></sup>]</tt>
     */
    public QuadraticIdeal[] precomputeGordonBrickell(QuadraticIdeal I, int n) {
	QuadraticIdeal[] powI = new QuadraticIdeal[n];

	for (int i = 0; i < n; i++) {
	    powI[i] = I;
	    I = square(I);
	}

	return powI;
    }

    private int[] determineNAF(FlexiBigInt e, int wi, int b) {
	int power2wi = 1 << wi;
	int j, u;
	int[] N = new int[b + 1];
	FlexiBigInt c = e.abs();
	int s = e.signum();

	j = 0;
	while (c.signum() > 0) {
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

    public QuadraticIdeal[][] precomputeSimPowerWNAF(QuadraticIdeal[] g, int w) {
	int power2w = 1 << (w + 1);
	int count = power2w >> 1;
	QuadraticIdeal[][] gE = new QuadraticIdeal[g.length][count];
	QuadraticIdeal A;

	for (int i = 0; i < g.length; i++) {
	    A = square(g[i]);
	    gE[i][0] = g[i];

	    for (int j = 1; j < count; j++) {
		gE[i][j] = multiply(gE[i][j - 1], A);
	    }
	}
	return gE;
    }

    public QuadraticIdeal simPowerWNAF(QuadraticIdeal[][] gLUT,
	    FlexiBigInt[] e, int w) {
	QuadraticIdeal A;
	int b, i, j;
	int k = e.length;
	int[][] N = new int[k][];

	for (i = k - 1, b = 0; i >= 0; i--) {
	    int bl;

	    bl = e[i].bitLength();
	    if (bl > b) {
		b = bl;
	    }
	}

	// determine the (w + 1) non-adjacent form for all exponents
	for (i = k - 1; i >= 0; i--) {
	    N[i] = determineNAF(e[i], w, b);
	}

	for (j = b, A = one(); j >= 0; j--) {
	    int n;

	    A = square(A);
	    for (i = 0; i < k; i++) {
		n = N[i][j];
		if (n == 0) {
		    continue;
		}

		A = (n > 0) ? multiply(A, gLUT[i][n >> 1]) : divide(A,
			gLUT[i][(-n) >> 1]);
	    }
	}

	return A;
    }

    /**
     * Simultaneous power computation for <= 10 ideals and exponents.
     * 
     * @param I
     *                the ideal array
     * @param n
     *                the exponent array
     * @return <tt>I[0]<sup>n[0]</sup> * ... * I[I.length-1]<sup>n[I.length-1]</sup></tt>,
     *         or one if <tt>I.length > 10</tt> or
     *         <tt>I.length != n.length</tt>
     */
    public QuadraticIdeal simPower(QuadraticIdeal[] I, FlexiBigInt[] n) {
	QuadraticIdeal[] Q;
	QuadraticIdeal C;
	int b, i, j, k, l;
	int m1, m2;
	int[] lut = new int[16];
	int maxBitLength = 0;
	FlexiBigInt[] e = new FlexiBigInt[n.length];
	for (i = n.length - 1; i >= 0; i--) {
	    e[i] = n[i];
	}

	k = I.length;

	// no more than 10 please. and please use the
	// same number of exponents and ideals.
	if (k > 10 || n.length != k) {
	    return one();
	}

	Q = new QuadraticIdeal[1 << k];

	// precomputations
	Q[0] = one();
	for (i = 0; i < k; i++) {
	    if (e[i].signum() < 0) {
		Q[1 << i] = invert(I[i]);
		e[i] = e[i].abs();
	    } else {
		Q[1 << i] = I[i];
	    }

	    l = e[i].bitLength();
	    if (l > maxBitLength) {
		maxBitLength = l;
	    }
	}

	for (l = 2; l <= k; l++) {
	    for (j = 0; j < l; j++) {
		lut[j] = j;
	    }

	    while (lut[l - 1] < k) {
		m1 = 1 << lut[0];
		m2 = 0;
		for (j = 1; j < l; j++) {
		    m2 |= 1 << lut[j];
		}
		Q[m1 + m2] = multiply(Q[m1], Q[m2]);

		lut[0]++;
		for (j = 0; j < l - 1; j++) {
		    if (lut[j] == lut[j + 1]) {
			lut[j] = j;
			lut[j + 1]++;
		    }
		}
	    }
	}

	// simultaneous exponentation
	C = one();
	for (i = maxBitLength; i >= 0; i--) {
	    b = 0;
	    for (j = 0; j < k; j++) {
		if (e[j].testBit(i)) {
		    b |= 1 << j;
		}
	    }

	    C = square(C);
	    C = multiply(C, Q[b]);
	}

	return C;
    }

    // /////////////////////////////////////////////////////////////////////////

    public QuadraticIdeal primePowerIdeal(FlexiBigInt p, int e)
	    throws NoQuadraticResidueException {
	FlexiBigInt a, b, s, t1;

	a = p;
	// b is the quadratic root modulo p of
	// the discriminant reduced modulo p
	b = IntegerFunctions.ressol(discriminant.mod(p), p);

	// delta and b have different parity
	if (discriminant.testBit(0) != b.testBit(0)) {
	    b = b.add(p);
	}

	// b^2 = Delta (mod 4 p)

	for (int j = 2; j <= e; j++) {
	    // r s = 1 (mod p)
	    s = b.modInverse(p);
	    t1 = discriminant.subtract(b.multiply(b));
	    t1 = t1.shiftRight(2).divide(a).multiply(s).mod(p);
	    b = b.add(t1.multiply(a).shiftLeft(1));
	    a = a.multiply(p);
	}

	return reduce(a, b);
    }

    public QuadraticIdeal randomPrimePowerIdeal(int bits, int e) {
	FlexiBigInt p;

	do {
	    p = new FlexiBigInt(bits, 20, prng);
	} while (IntegerFunctions.jacobi(discriminant.mod(p), p) != 1);

	// XXX --rpw 2001/10/17 fix this.
	try {
	    return primePowerIdeal(p, e);
	} catch (NoQuadraticResidueException nqre) {
	    return one();
	}
    }

    public QuadraticIdeal randomIdeal() {
	QuadraticIdeal I;

	I = randomPrimePowerIdeal(70, prng.nextInt()
		% RANDOM_PRIME_POWER_IDEAL_EXPONENT);
	for (int i = 0; i < RANDOM_IDEAL_ITERATIONS; i++) {
	    I = multiply(I, randomPrimePowerIdeal(
		    RANDOM_PRIME_POWER_IDEAL_BITLENGTH, prng.nextInt()
			    % RANDOM_PRIME_POWER_IDEAL_EXPONENT));
	}
	return I;
    }

    // ////////////////////////////////////////////////////////////////////////
}
