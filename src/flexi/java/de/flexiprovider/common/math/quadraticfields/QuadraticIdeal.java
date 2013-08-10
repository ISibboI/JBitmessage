package de.flexiprovider.common.math.quadraticfields;

import de.flexiprovider.common.exceptions.NoQuadraticResidueException;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.math.IntegerFunctions;

public class QuadraticIdeal {

    protected FlexiBigInt a;

    protected FlexiBigInt b;

    private static final int PRIME_CERTAINTY = 42;

    public QuadraticIdeal(FlexiBigInt a, FlexiBigInt b) {
	this.a = a;
	this.b = b;
    }

    public QuadraticIdeal(int a, int b) {
	this.a = FlexiBigInt.valueOf(a);
	this.b = FlexiBigInt.valueOf(b);
    }

    public boolean equals(Object other) {
	if (!(other instanceof QuadraticIdeal)) {
	    return false;
	}
	QuadraticIdeal otherIdeal = (QuadraticIdeal) other;

	return a.equals(otherIdeal.a) && b.equals(otherIdeal.b);
    }

    public String toString() {
	return "(" + a + ", " + b + ")";
    }

    public FlexiBigInt getA() {
	return a;
    }

    public FlexiBigInt getB() {
	return b;
    }

    public byte[] idealToOctets(FlexiBigInt discriminant, boolean compress) {
	return idealToOctets(new IQClassGroup(discriminant), compress);
    }

    public byte[] idealToOctets(IQClassGroup classGroup, boolean compress) {
	FlexiBigInt a, b;
	FlexiBigInt tmp = classGroup.getDiscriminant().abs();

	tmp = IntegerFunctions.squareRoot(tmp.divide(FlexiBigInt.valueOf(3)));
	int r = (tmp.bitLength() + 7) >> 3;

	// reduce ideal if necessary
	if (!classGroup.isReduced(this)) {
	    QuadraticIdeal reducedIdeal = classGroup.reduce(this);
	    a = reducedIdeal.a;
	    b = reducedIdeal.b;
	} else {
	    a = this.a;
	    b = this.b;
	}

	byte[] M, X = IntegerFunctions.integerToOctets(a);

	// check whether compression requested and the first
	// component of the ideal tuple is a prime
	if (compress && a.isProbablePrime(PRIME_CERTAINTY)) {
	    // byte arrays are zero initialized in java
	    M = new byte[r + 1];
	    M[0] = (b.signum() >= 0) ? (byte) 0x02 : (byte) 0x03;
	    System.arraycopy(X, 0, M, 1, r - X.length + 1);
	} else {
	    // byte arrays are zero initialized in java
	    byte[] Y = IntegerFunctions.integerToOctets(b);
	    M = new byte[(r << 1) + 1];
	    M[0] = (b.signum() >= 0) ? (byte) 0x04 : (byte) 0x05;
	    System.arraycopy(X, 0, M, r - X.length + 1, X.length);
	    System.arraycopy(Y, 0, M, (r << 1) - Y.length + 1, Y.length);
	}

	return M;
    }

    public static QuadraticIdeal octetsToIdeal(FlexiBigInt discriminant,
	    byte[] M) throws IQEncodingException {
	QuadraticIdeal I = null;
	IQClassGroup classGroup = new IQClassGroup(discriminant);
	FlexiBigInt tmp = IntegerFunctions.squareRoot(discriminant.abs()
		.divide(FlexiBigInt.valueOf(3)));
	int r = (tmp.bitLength() + 7) >> 3;
	int m = M.length - 1;

	if (m == r) {
	    if (M[0] != 0x02 && M[0] != 0x03) {
		throw new IQEncodingException(
			"invalid encoding of a quadratic ideal detected (1)");
	    }

	    FlexiBigInt p = IntegerFunctions.octetsToInteger(M, 1, m);

	    if (IntegerFunctions.jacobi(discriminant, p) == -1
		    || !p.isProbablePrime(PRIME_CERTAINTY)) {
		throw new IQEncodingException(
			"invalid encoding of a quadratic ideal detected (2)");
	    }

	    try {
		I = classGroup.primePowerIdeal(p, 1);
	    } catch (NoQuadraticResidueException nqre) {
		throw new IQEncodingException(
			"invalid encoding of a quadratic ideal detected (3)");
	    }

	    if (M[0] == 0x03) {
		I = classGroup.invert(I);
	    }
	} else if (m == (r << 1)) {
	    if (M[0] != 0x04 && M[0] != 0x05) {
		throw new IQEncodingException(
			"invalid encoding of a quadratic ideal detected (4)");
	    }
	    FlexiBigInt a = IntegerFunctions.octetsToInteger(M, 1, r);
	    FlexiBigInt b = IntegerFunctions.octetsToInteger(M, r + 1, r);

	    if (M[0] == 0x05) {
		b = b.negate();
	    }
	    if (b.multiply(b).subtract(discriminant).remainder(
		    a.multiply(FlexiBigInt.valueOf(4))).signum() != 0) {
		throw new IQEncodingException(
			"invalid encoding of a quadratic ideal detected (5)");
	    }

	    I = new QuadraticIdeal(a, b);
	} else {
	    throw new IQEncodingException(
		    "invalid encoding of a quadratic ideal detected (6)");
	}

	return I;
    }

    public int hashCode() {
	return a.hashCode() + b.hashCode();
    }

}
