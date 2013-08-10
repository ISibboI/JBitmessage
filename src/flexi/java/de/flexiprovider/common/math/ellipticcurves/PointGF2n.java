/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */
package de.flexiprovider.common.math.ellipticcurves;

import java.util.Random;

import de.flexiprovider.common.exceptions.DifferentCurvesException;
import de.flexiprovider.common.exceptions.DifferentFieldsException;
import de.flexiprovider.common.exceptions.InvalidFormatException;
import de.flexiprovider.common.exceptions.InvalidPointException;
import de.flexiprovider.common.math.finitefields.GF2nElement;
import de.flexiprovider.common.math.finitefields.GF2nField;
import de.flexiprovider.common.math.finitefields.GF2nONBElement;
import de.flexiprovider.common.math.finitefields.GF2nONBField;
import de.flexiprovider.common.math.finitefields.GF2nPolynomialElement;
import de.flexiprovider.common.math.finitefields.GF2nPolynomialField;
import de.flexiprovider.common.math.finitefields.GFElement;

/**
 * This class implements points and their arithmetic on elliptic curves over
 * finite fields with characteristic 2 (GF(2<sup>n</sup>)). A Point P = (x, y)
 * is the tupel x, y that solves the equation y<sup>2</sup> + xy = x<sup>3</sup> +
 * ax<sup>2</sup> + b, x and y in GF(2<sup>n</sup>).
 * <p>
 * Points on elliptic curves can be added and subtracted. Since each of these
 * operations require a field inversion in GF(2<sup>n</sup>), which is
 * expensive, this class calculates with projective coordinates to avoid these
 * inversions. The equation for the elliptic curve is as follows:<br>
 * Y<SUP>2</SUP>Z<SUP>6</SUP> + XYZ<SUP>5</SUP> = X<SUP>3</SUP>Z<SUP>6</SUP> +
 * aX<SUP>2</SUP>Z<SUP>4</SUP> + b, <br>
 * with x = X/Z<SUP>2</SUP> and y = Y/Z<SUP>3</SUP>.
 * <p>
 * For the formulas of the projective addition and doubling
 * {@link #add(Point) add} and {@link #multiplyBy2 multiplyBy2}, respectively.
 * 
 * @author Birgit Henhapl
 * @author Vangelis Karatsiolis
 * @see de.flexiprovider.common.math.ellipticcurves.EllipticCurveGF2n
 * @see de.flexiprovider.common.math.ellipticcurves.Point
 * @see de.flexiprovider.common.math.finitefields.GF2nField
 * @see de.flexiprovider.common.math.finitefields.GF2nElement
 */
public class PointGF2n extends Point {

    // /////////////////////////////////////////////////////////////
    // member variables
    // /////////////////////////////////////////////////////////////

    /**
     * the extension degree of the underlying field
     */
    private int mDeg;

    /**
     * the underlying field
     */
    private GF2nField mGF2n;

    private boolean isGF2nONBField = false;

    /**
     * curve parameter a
     */
    private GF2nElement mA;

    /**
     * flag indicating whether mA is zero
     */
    private boolean mAIsZero;

    /**
     * curve parameter b
     */
    private GF2nElement mB;

    /**
     * x-coordinate of this <tt>PointGF2n</tt>.
     */
    private GF2nElement mX;

    /**
     * y-coordinate of this <tt>PointGF2n</tt>.
     */
    private GF2nElement mY;

    /**
     * z-coordinate of this <tt>PointGF2n</tt>.
     */
    private GF2nElement mZ;

    // /////////////////////////////////////////////////////////////
    // constructors
    // /////////////////////////////////////////////////////////////

    /**
     * Construct the point at infinity on the specified elliptic curve
     * 
     * @param E
     *                the elliptic curve this point lies on
     */
    public PointGF2n(EllipticCurveGF2n E) {
	mE = E;
	mP = E.getQ();
	mA = (GF2nElement) E.getA();
	mAIsZero = mA.isZero();
	mB = (GF2nElement) E.getB();
	mGF2n = mA.getField();
	mDeg = mGF2n.getDegree();
	setGF2nFieldType();
	assignZero();
    }

    /**
     * Construct a random point on the specified elliptic curve using the given
     * source of randomness.
     * 
     * @param E
     *                the elliptic curve this point lies on
     * @param rand
     *                the source of randomness
     */
    public PointGF2n(EllipticCurveGF2n E, Random rand) {
	mE = E;
	mP = E.getQ();
	mA = (GF2nElement) E.getA();
	mAIsZero = mA.isZero();
	mB = (GF2nElement) E.getB();
	mGF2n = mA.getField();
	mDeg = mGF2n.getDegree();
	setGF2nFieldType();

	GF2nElement right;
	do {
	    do {
		mX = createRandomGF2nElement(mGF2n, rand);
	    } while (mX.isZero());

	    // right = x^3 + a*x^2 + b
	    mY = mX.square();
	    right = (GF2nElement) mA.multiply(mY);
	    right.addToThis(mB);
	    right.addToThis(mY.multiply(mX));

	    // y = x^(-2)
	    mY = (GF2nElement) mY.invert();

	    // right = x^(-2) * (x^3 + a*x^2 + b) ->
	    // (y/x)^2 + (y/x) = (x^3 + a*x^2 + b)/x^2 ->
	    // z^2 + z = (x^3 + a*x^2 + b)/x^2
	    right.multiplyThisBy(mY);

	    // while not found (right.trace() != 0)
	} while (right.trace() != 0);

	mY = right.solveQuadraticEquation();
	if (mY.testRightmostBit()) {
	    mY.increaseThis();
	}
	mY.multiplyThisBy(mX);
	mZ = createGF2nOneElement(mGF2n);
    }

    /**
     * Constructs point with specified parameters. This method throws an
     * <tt>InvalidPointException</tt>, if (<tt>x</tt>, <tt>y</tt>) is
     * not on curve <tt>E</tt>.
     * 
     * @param x
     *                x-coordinate
     * @param y
     *                y-coordinate
     * @param E
     *                EllipticCurveGF2n is the elliptic curve this point lies on
     * @throws InvalidPointException
     *                 if the specified point is not on the curve.
     * @throws DifferentFieldsException
     *                 if <tt>x</tt> and <tt>y</tt> are defined over
     *                 different fields.
     */
    public PointGF2n(GF2nElement x, GF2nElement y, EllipticCurveGF2n E)
	    throws InvalidPointException, DifferentFieldsException {

	mE = E;
	mP = E.getQ();
	mA = (GF2nElement) E.getA();
	mAIsZero = mA.isZero();
	mB = (GF2nElement) E.getB();
	mGF2n = mA.getField();
	mDeg = mGF2n.getDegree();
	setGF2nFieldType();

	mX = (GF2nElement) x.clone();
	mY = (GF2nElement) y.clone();
	mZ = createGF2nOneElement(mGF2n);
    }

    /**
     * Constructs point with specified parameters. This method throws an
     * <tt>InvalidPointException</tt>, if (<tt>x</tt>, <tt>y</tt>) is
     * not on curve <tt>E</tt>.
     * 
     * @param x
     *                x-coordinate
     * @param y
     *                y-coordinate
     * @param z
     *                z-coordinate
     * @param E
     *                the elliptic curve this point lies on
     * @throws InvalidPointException
     *                 if the specified point is not on the curve.
     * @throws DifferentFieldsException
     *                 if <tt>x</tt>, <tt>y</tt>, and <tt>z</tt> are
     *                 defined over different fields.
     */
    public PointGF2n(GF2nElement x, GF2nElement y, GF2nElement z,
	    EllipticCurveGF2n E) throws InvalidPointException,
	    DifferentFieldsException {

	mE = E;
	mP = E.getQ();
	mA = (GF2nElement) E.getA();
	mAIsZero = mA.isZero();
	mB = (GF2nElement) E.getB();
	mGF2n = mA.getField();
	mDeg = mGF2n.getDegree();
	setGF2nFieldType();

	mX = (GF2nElement) x.clone();
	mY = (GF2nElement) y.clone();
	mZ = (GF2nElement) z.clone();
    }

    /**
     * Constructs a new point. The information is packed in the given byte array
     * together with the given elliptic curve. (see X9.63-199x)
     * 
     * @param encoded
     *                the point in normal, compressed or hybrid form.
     * @param E
     *                the underlying elliptic curve
     * @throws InvalidPointException
     *                 if the point is not on the curve.
     * @throws InvalidFormatException
     *                 if the point representation is invalid.
     */
    public PointGF2n(byte[] encoded, EllipticCurveGF2n E)
	    throws InvalidPointException, InvalidFormatException {

	mE = E;
	mP = E.getQ();
	mA = (GF2nElement) E.getA();
	mAIsZero = mA.isZero();
	mB = (GF2nElement) E.getB();
	mGF2n = mA.getField();
	mDeg = mGF2n.getDegree();
	setGF2nFieldType();

	// the zero point is encoded as a single byte 0
	if (encoded.length == 1 && encoded[0] == 0) {
	    assignZero();
	    return;
	}

	byte[] bX, bY;

	final byte pc = encoded[0];

	switch (pc) {

	case 2:
	case 3:
	    // compressed form
	    bX = new byte[encoded.length - 1];
	    System.arraycopy(encoded, 1, bX, 0, bX.length);
	    mX = createGF2nElement(bX);
	    boolean yMod2 = (pc & 0x01) == 1;
	    mY = decompress(yMod2, mX);
	    break;

	case 4:
	    // uncompressed form
	    int l = (encoded.length - 1) >> 1;
	    bX = new byte[l];
	    bY = new byte[l];
	    System.arraycopy(encoded, 1, bX, 0, l);
	    System.arraycopy(encoded, 1 + l, bY, 0, l);
	    mX = createGF2nElement(bX);
	    mY = createGF2nElement(bY);
	    break;

	case 6:
	case 7:
	    // hybrid form
	    l = (encoded.length - 1) >> 1;
	    bX = new byte[l];
	    bY = new byte[l];
	    System.arraycopy(encoded, 1, bX, 0, l);
	    System.arraycopy(encoded, 1 + l, bY, 0, l);
	    mX = createGF2nElement(bX);
	    mY = createGF2nElement(bY);
	    yMod2 = (pc & 0x01) == 1;
	    if (!(decompress(yMod2, mX).equals(mY))) {
		throw new InvalidPointException();
	    }
	    break;

	default:
	    throw new InvalidFormatException(pc);
	}

	mZ = createGF2nOneElement(mGF2n);
    }

    /**
     * Copy constructor.
     * 
     * @param other
     *                point to copy
     */
    public PointGF2n(PointGF2n other) {
	EllipticCurveGF2n E = (EllipticCurveGF2n) other.getE();
	mE = E;
	mP = E.getQ();
	mA = (GF2nElement) E.getA();
	mAIsZero = mA.isZero();
	mB = (GF2nElement) E.getB();
	mGF2n = mA.getField();
	mDeg = mGF2n.getDegree();
	setGF2nFieldType();

	assign(other);
    }

    // /////////////////////////////////////////////////////////////
    // assignments
    // /////////////////////////////////////////////////////////////

    /**
     * Assigns to this point the point at infinity. The coordinates of this
     * point are (x, y, z) = (1, 1, 0).
     */
    private void assignZero() {
	mX = createGF2nOneElement(mGF2n);
	mY = createGF2nOneElement(mGF2n);
	mZ = createGF2nZeroElement(mGF2n);
    }

    /**
     * Assigns to this point the x-, y- and z-coordinates (<tt>x</tt>,
     * <tt>y</tt>, <tt>z</tt>) (without copying).
     * 
     * @param x
     *                FlexiBigInt is the x-coordinate
     * @param y
     *                FlexiBigInt is the y-coordinate
     * @param z
     *                FlexiBigInt is the z-coordinate
     */
    private void assign(GF2nElement x, GF2nElement y, GF2nElement z)
	    throws InvalidPointException {
	mX = x;
	mY = y;
	mZ = z;
    }

    /**
     * Assigns to this point the x-, y- and z-coordinates of the given other
     * point (by copying the coordinates).
     * 
     * @param other
     *                the other point
     */
    private void assign(PointGF2n other) {
	mX = (GF2nElement) other.mX.clone();
	mY = (GF2nElement) other.mY.clone();
	mZ = (GF2nElement) other.mZ.clone();
    }

    /**
     * @return a clone of this point
     */
    public Object clone() {
	return new PointGF2n(this);
    }

    /**
     * Tests whether this point is equal to <tt>other</tt>.
     * 
     * @param other
     *                point to compare this point with
     * @return <tt>true</tt> if <tt>this</tt> == <tt>other</tt><br>
     *         <tt>false</tt> if <tt>this</tt> != <tt>other</tt>
     */
    public boolean equals(Object other) {

	// Guard against other==null or being of an unsuitable type:
	if (other == null || !(other instanceof PointGF2n)) {
	    return false;
	}

	PointGF2n otherPoint = (PointGF2n) other;

	if (mZ.isOne() && otherPoint.mZ.isOne()) {
	    return mX.equals(otherPoint.mX) && mY.equals(otherPoint.mY);
	}

	boolean result = true;

	if (mZ.isOne()) {
	    // z2 = ((PointGF2n)other).mZ^2
	    GFElement z2 = otherPoint.mZ.square();

	    // mX*z2 = ((PointGF2n)other).mX ?
	    result = result && otherPoint.mX.equals(mX.multiply(z2));

	    // z2 = ((PointGF2n)other).mZ^3
	    z2.multiplyThisBy(otherPoint.mZ);

	    // mY*z2 = P mY?
	    result = result && otherPoint.mY.equals(mY.multiply(z2));

	} else if (otherPoint.mZ.isOne()) {
	    // z1 = mZ^2
	    GFElement z1 = mZ.square();

	    // ((PointGF2n)other).mX*z1 = mX ?
	    result = result && mX.equals(otherPoint.mX.multiply(z1));

	    // z1 = mZ^3
	    z1.multiplyThisBy(mZ);

	    // ((PointGF2n)other).mY*z1 = mY?
	    //
	    result = result && mY.equals(otherPoint.mY.multiply(z1));

	} else {
	    // z1 = mZ^2
	    GFElement z1 = mZ.square();

	    // z2 = ((PointGF2n)other).mZ^2
	    GFElement z2 = otherPoint.mZ.square();

	    // mX*((PointGF2n)other).mZ^2 = ((PointGF2n)other).mX*mZ^2 ?
	    result = result
		    && mX.multiply(z2).equals(otherPoint.mX.multiply(z1));

	    // z1 = mZ^3
	    z1.multiplyThisBy(mZ);

	    // z2 = ((PointGF2n)other).mZ^3
	    z2.multiplyThisBy(otherPoint.mZ);

	    // mX*((PointGF2n)other).mZ^2 = ((PointGF2n)other).mX*mZ^2 ?
	    result = result
		    && mY.multiply(z2).equals(otherPoint.mY.multiply(z1));

	}

	return result;
    }

    /**
     * @return the hash code of this point
     * @see java.lang.Object#hashCode()
     */
    public int hashCode() {
	// Two projective points are equal iff their corresponding
	// affine representations are equal. We cannot simply sum over the
	// (hash values of) projective coordinates because the projective
	// representation is not unique: a given point (x,y) might be
	// represented as (X,Y,Z) or (X',Y',Z').
	//
	// This hash code could possibly be precomputed whenever the value of
	// this point changes.
	return getXAffin().hashCode() + getYAffin().hashCode();
    }

    /**
     * Returns this point in affine representation as a String: (x, y), where x =
     * <tt>mX</tt>/<tt>mZ<sup>2</sup></tt> and y = <tt>mZ</tt>/<tt>mZ<sup>3</sup></tt>.
     * If this point is at infinity (that means, mZ = 0), the output is (0, 0).
     * 
     * @return String (x, y)
     */
    public String toString() {
	return "(" + getXAffin().toString(16) + ",\n "
		+ getYAffin().toString(16) + ")";
    }

    // ///////////////////////////////////////////////////////////
    // access
    // ///////////////////////////////////////////////////////////

    /**
     * @return the x-coordinate of this point
     */
    public GFElement getX() {
	return mX;
    }

    /**
     * @return the y-coordinate of this point
     */
    public GFElement getY() {
	return mY;
    }

    /**
     * @return the z-coordinate of this point
     */
    public GFElement getZ() {
	return mZ;
    }

    /**
     * Return the x-coordinate of this point in affine representation. In this
     * class, the projective representation x = X/Z<sup>2</sup> and y = Y/Z<sup>3</sup>
     * is chosen to speed up point addition. This method returns the
     * x-coordinate in affine representation.
     * 
     * @return the x-coordinate of this point in affine representation
     */
    public GFElement getXAffin() {
	if (isZero()) {
	    // mZ equals zero.
	    return (GF2nElement) mZ.clone();
	} else if (mZ.isOne()) {
	    return mX;
	} else {
	    GFElement z;
	    z = mZ.square();
	    z = z.invert();
	    z.multiplyThisBy(mX);
	    return z;
	}
    }

    /**
     * Return the y-coordinate of this point in affine representation. In this
     * class, the projective representation x = X/Z<sup>2</sup> and y = Y/Z<sup>3</sup>
     * is chosen to speed up point addition. This method returns the
     * y-coordinate in affine representation.
     * 
     * @return the y-coordinate of this point in affine representation
     */
    public GFElement getYAffin() {
	if (isZero()) {
	    // mZ equals zero.
	    return (GFElement) mZ.clone();
	} else if (mZ.isOne()) {
	    return (GFElement) mY.clone();
	} else {
	    GFElement z = null;
	    // z = mZ^(-3) * mY ?
	    z = mZ.square();
	    z.multiplyThisBy(mZ);
	    z = z.invert();
	    z.multiplyThisBy(mY);
	    return z;
	}
    }

    /**
     * @return <tt>this</tt> in affine coordinates
     */
    public Point getAffin() {
	if (isZero()) {
	    return this;
	}

	GF2nElement notZ = (GF2nElement) mZ.invert();
	GF2nElement squareNotZ = notZ.square();
	GF2nElement x = (GF2nElement) mX.multiply(squareNotZ);

	// z = mZ^(-3) * mY
	notZ.multiplyThisBy(squareNotZ);
	GF2nElement y = (GF2nElement) mY.multiply(notZ);

	return new PointGF2n(x, y, (EllipticCurveGF2n) mE);
    }

    /**
     * Tests whether this point is on the curve mE. This method returns
     * <tt>true</tt>, if <br>
     * <tt><tt>mY</tt><sup>2</sup> -
     * <tt>mX</tt><sup>3</sup> - <tt>mA</tt>*<tt>mX</tt>*
     * <tt>mZ</tt><sup>4</sup> - <tt>mB</tt>*<tt>mZ</tt><sup>6</sup>
     * = 0</tt>,<br>
     * otherwise <tt>false</tt>.
     * 
     * @return <tt><tt>mY</tt><sup>2</sup> - <tt>mX</tt>
     * <sup>3</sup> - <tt>mA</tt>*<tt>mX</tt>*<tt>mZ</tt>
     * <sup>4</sup> - <tt>mB</tt>*<tt>mZ</tt><sup>6</sup> == 0</tt>
     * @see de.flexiprovider.common.math.ellipticcurves.EllipticCurveGF2n
     */
    public boolean onCurve() {

	if (isZero()) {
	    return true;
	}

	GFElement left, right, tmp;

	if (mZ.isOne()) {
	    right = mX.square(); // right = x^2
	    tmp = right.multiply(mX); // tmp = x^3

	    // right = ax^2
	    //
	    right.multiplyThisBy(mA);

	    // right = x^3 + ax^2
	    //
	    right.addToThis(tmp);

	    // right = x^3 + ax^2 + b
	    //
	    right.addToThis(mB);
	    left = mX.multiply(mY); // left = xy

	    // left = y^2 + xy
	    //
	    left.addToThis(mY.square());
	} else {
	    right = mX.square(); // right = x^2
	    tmp = right.multiply(mX); // tmp = x^3

	    // right = ax^2
	    //
	    right.multiplyThisBy(mA);
	    left = mZ.square(); // left = z^2

	    // right = ax^2z^2
	    //
	    right.multiplyThisBy(left);

	    // right = x^3 + ax^2z^2
	    //
	    right.addToThis(tmp);
	    tmp = ((GF2nElement) left).square(); // tmp = z^4

	    // left = z^6
	    //
	    left.multiplyThisBy(tmp);

	    // right = x^3 + ax^2z^2 + bz^6
	    //
	    right.addToThis(left.multiply(mB));
	    left = mX.multiply(mY); // left = xy

	    // left = xyz
	    //
	    left.multiplyThisBy(mZ);

	    // left = y^2 + xyz
	    //
	    left.addToThis(mY.square());
	}

	return right.equals(left);
    }

    /**
     * @return flag indicating whether this is the point at infinity
     */
    public boolean isZero() {
	return mX.isOne() && mY.isOne() && mZ.isZero();
    }

    // ////////////////////////////////////////////////////////////////////
    // arithmetic
    // ////////////////////////////////////////////////////////////////////

    /**
     * Adds to this point the point <tt>other</tt>. <br>
     * The algorithm is due to Chudnovsky and Chudnovsky:<br>
     * <tt>input : (X<sub>0</sub>, Y<sub>0</sub>, Z<sub>0</sub>),
     * (X<sub>1</sub>, Y<sub>1</sub>, Z<sub>1</sub>)</tt><br>
     * <tt>output: (X<sub>0</sub>, Y<sub>0</sub>, Z<sub>0</sub>) +
     * (X<sub>1</sub>, Y<sub>1</sub>, Z<sub>1</sub>) =
     * (X<sub>2</sub>, Y<sub>2</sub>, Z<sub>2</sub>)<br><br>
     *
     * U<sub>0</sub> = X<sub>0</sub>Z<sub>1</sub><sup>2</sup><br>
     * S<sub>0</sub> = Y<sub>0</sub>Z<sub>1</sub><sup>3</sup><br>
     * U<sub>1</sub> = X<sub>1</sub>Z<sub>0</sub><sup>2</sup><br>
     * W = U<sub>0</sub> + U<sub>1</sub><br>
     * S<sub>1</sub> = Y<sub>1</sub>Z<sub>0</sub><sup>3</sup><br>
     * R = S<sub>0</sub> + S<sub>1</sub><br>
     * L = Z<sub>0</sub>W
     * V = RX<sup>1</sup> + LY<sub>1</sub><br>
     * Z<sub>2</sub> = LZ<sub>1</sub><br>
     * T = R + Z<sub>2</sub><br>
     * X<sub>2</sub> = aZ<sub>2</sub><sup>2</sup> + TR<sup>2</sup> + W<sup>3</sup><br>
     * Y<sub>2</sub> = TX<sub>2</sub> + VL<sup>2</sup></tt><br>
     * 
     * @param other
     *                point to add to this point
     * @return <tt>this + other</tt>
     * @throws DifferentCurvesException
     *                 if <tt>this</tt> and <tt>other</tt> are not on the
     *                 same curve.
     */
    public Point add(Point other) throws DifferentCurvesException {
	PointGF2n result = new PointGF2n(this);
	result.addToThis(other);
	return result;
    }

    /**
     * Adds to this point the point <tt>other</tt>. <br>
     * The algorithm is due to Chudnovsky and Chudnovsky:<br>
     * <tt>input : (X<sub>0</sub>, Y<sub>0</sub>, Z<sub>0</sub>),
     * (X<sub>1</sub>, Y<sub>1</sub>, Z<sub>1</sub>)</tt><br>
     * <tt>output: (X<sub>0</sub>, Y<sub>0</sub>, Z<sub>0</sub>) +
     * (X<sub>1</sub>, Y<sub>1</sub>, Z<sub>1</sub>) =
     * (X<sub>2</sub>, Y<sub>2</sub>, Z<sub>2</sub>)<br><br>
     *
     * U<sub>0</sub> = X<sub>0</sub>Z<sub>1</sub><sup>2</sup><br>
     * S<sub>0</sub> = Y<sub>0</sub>Z<sub>1</sub><sup>3</sup><br>
     * U<sub>1</sub> = X<sub>1</sub>Z<sub>0</sub><sup>2</sup><br>
     * W = U<sub>0</sub> + U<sub>1</sub><br>
     * S<sub>1</sub> = Y<sub>1</sub>Z<sub>0</sub><sup>3</sup><br>
     * R = S<sub>0</sub> + S<sub>1</sub><br>
     * L = Z<sub>0</sub>W
     * V = RX<sup>1</sup> + LY<sub>1</sub><br>
     * Z<sub>2</sub> = LZ<sub>1</sub><br>
     * T = R + Z<sub>2</sub><br>
     * X<sub>2</sub> = aZ<sub>2</sub><sup>2</sup> + TR<sup>2</sup> + W<sup>3</sup><br>
     * Y<sub>2</sub> = TX<sub>2</sub> + VL<sup>2</sup></tt><br>
     * 
     * @param other
     *                point to add to this point
     * @throws DifferentCurvesException
     *                 if <tt>this</tt> and <tt>other</tt> are not on the
     *                 same curve.
     */
    public void addToThis(Point other) throws DifferentCurvesException {

	if (!(other instanceof PointGF2n)) {
	    throw new DifferentCurvesException(
		    "PointGF2n.addToThis(Point P): other is not an instance"
			    + " of PointGF2n");
	}

	PointGF2n otherPoint = (PointGF2n) other;

	// this point is at infinity
	if (isZero()) {
	    assign(otherPoint);
	} else if (!otherPoint.isZero()) {

	    GF2nElement T1, T2, T3, T4, T5, T6;
	    GFElement T7, T8, T9;

	    T1 = (GF2nElement) mX.clone();
	    T2 = (GF2nElement) mY.clone();
	    T3 = (GF2nElement) mZ.clone();
	    T4 = (GF2nElement) otherPoint.mX.clone();
	    T5 = (GF2nElement) otherPoint.mY.clone();
	    T6 = (GF2nElement) otherPoint.mZ.clone();

	    if (!otherPoint.mZ.isOne()) {
		T7 = T6.square();
		T1.multiplyThisBy(T7); // = U0 (if Z1 != 1)
		T7.multiplyThisBy(T6);
		T2.multiplyThisBy(T7); // = S0 (if Z1 != 1)
	    }
	    T7 = T3.square();
	    T8 = T4.multiply(T7); // = U1
	    T1.addToThis(T8); // = W
	    T7.multiplyThisBy(T3);
	    T8 = T5.multiply(T7); // = S1
	    T2.addToThis(T8); // = R

	    if (T1.isZero() && T2.isZero()) {
		multiplyThisBy2();
	    } else if (T1.isZero() && !T2.isZero()) {
		assignZero();
	    } else {
		T4.multiplyThisBy(T2);
		T3.multiplyThisBy(T1); // = L (= Z2 if Z1 = 1)
		T5.multiplyThisBy(T3);
		T4.addToThis(T5); // = V
		T5 = T3.square();
		T7 = T4.multiply(T5);
		if (!otherPoint.mZ.isOne()) {
		    T3.multiplyThisBy(T6); // = Z2 (if Z1 != 1)
		}
		T4 = (GF2nElement) T2.add(T3); // = T
		T2.multiplyThisBy(T4);
		T5 = T1.square();
		T1.multiplyThisBy(T5);
		if (!mAIsZero) {
		    T8 = T3.square();
		    T9 = mA.multiply(T8);
		    T1.addToThis(T9);
		}
		T1.addToThis(T2); // = X2
		T4.multiplyThisBy(T1);
		T4.addToThis(T7); // = Y2

		assign(T1, T4, T3);
	    }
	}

    }

    /**
     * Adds in affine coordinates to this point the point <code>other</code>.
     * 
     * @param other
     *                point to add to this point
     * @exception DifferentCurvesException
     *                    when <code>other</code> is defined over another
     *                    curve
     * @return <code>this</code> + <code>other</code> in affine coordinates
     */
    public Point addAffine(Point other) {
	PointGF2n p = (PointGF2n) this.getAffin();
	PointGF2n o = (PointGF2n) other.getAffin();

	if (isZero()) {
	    return new PointGF2n(o);
	}

	if (o.isZero()) {
	    return new PointGF2n(p);
	}

	GF2nElement pX = p.mX;
	GF2nElement pY = p.mY;
	GF2nElement oX = o.mX;
	GF2nElement oY = o.mY;

	// P == other -> double(P)
	if ((pX.equals(oX)) && (pY.equals(oY))) {
	    return p.multiplyBy2Affine();
	}

	GF2nElement tmp = (GF2nElement) pY.add(oY);
	GF2nElement lambda = (GF2nElement) pX.add(oX).invert();
	lambda = (GF2nElement) lambda.multiply(tmp);

	GF2nElement x = (GF2nElement) lambda.square().add(lambda);
	x = (GF2nElement) x.add(pX).add(oX)
		.add(((EllipticCurveGF2n) mE).getA());

	GF2nElement y = (GF2nElement) pX.add(x).multiply(lambda);
	y = (GF2nElement) y.add(x).add(pY);

	return new PointGF2n(x, y, (EllipticCurveGF2n) mE);
    }

    /**
     * Doubles this point. <br>
     * input : <tt>(X<sub>1</sub>, Y<sub>1</sub>, Z<sub>1</sub>)</tt><br>
     * output: <tt>2*(X<sub>1</sub>, Y<sub>1</sub>, Z<sub>1</sub>)
     * = (X<sub>2</sub>, Y<sub>2</sub>, Z<sub>2</sub>)</tt><br>
     * <br>
     * <tt>c = b<sup>2<sup>m-2</sup></sup>,<br>
     * Z<sub>2</sub> = X<sub>1</sub>Z<sub>1</sub><sup>2</sup><br>
     * X<sub>2</sub> = (X<sub>1</sub> + cZ<sub>1</sub><sup>2</sup>)<sup>4</sup><br>
     * U = Z<sub>2</sub> + X<sub>1</sub><sup>2</sup> + Y<sub>1</sub>Z<sub>1</sub><br>
     * Y<sub>2</sub> = X<sub>1</sub><sub>4</sub>Z<sub>2</sub> + UX<sub></sub>2</tt><br>
     * 
     * @return 2*this
     */
    public Point multiplyBy2() {
	PointGF2n result = new PointGF2n(this);
	result.multiplyThisBy2();
	return result;
    }

    /**
     * Doubles this point. <br>
     * input : <tt>(X<sub>1</sub>, Y<sub>1</sub>, Z<sub>1</sub>)</tt><br>
     * output: <tt>2*(X<sub>1</sub>, Y<sub>1</sub>, Z<sub>1</sub>)
     * = (X<sub>2</sub>, Y<sub>2</sub>, Z<sub>2</sub>)</tt><br>
     * <br>
     * <tt>c = b<sup>2<sup>m-2</sup></sup>,<br>
     * Z<sub>2</sub> = X<sub>1</sub>Z<sub>1</sub><sup>2</sup><br>
     * X<sub>2</sub> = (X<sub>1</sub> + cZ<sub>1</sub><sup>2</sup>)
     * <sup>4</sup><br>
     * U = Z<sub>2</sub> + X<sub>1</sub><sup>2</sup> + Y<sub>1</sub>Z
     * n <sub>1</sub><br>
     * Y<sub>2</sub> = X<sub>1</sub><sub>4</sub>Z<sub>2</sub> + UX<sub></sub>
     * 2</tt><br>
     */
    public void multiplyThisBy2() {

	GF2nElement T1, T2, T3, T4;

	// if this point is zero, do nothing!
	//
	if (!isZero()) {

	    T1 = (GF2nElement) mX.clone();
	    T2 = (GF2nElement) mY.clone();
	    T3 = (GF2nElement) mZ.clone();
	    T4 = (GF2nElement) mB.clone();

	    for (int i = 1; i < mDeg - 1; i++) {
		T4.squareThis();
	    }

	    if (T1.isZero() || T3.isZero()) {
		assignZero();
	    } else {

		T2.multiplyThisBy(T3);
		T3.squareThis();
		T4.multiplyThisBy(T3);
		T3.multiplyThisBy(T1); // = Z2

		T2.addToThis(T3);
		T4.addToThis(T1);
		T4.squareThis();
		T4.squareThis(); // = X2
		T1.squareThis();
		T2.addToThis(T1); // = U

		T2.multiplyThisBy(T4);
		T1.squareThis();
		T1.multiplyThisBy(T3);
		T2.addToThis(T1); // = Y2
	    }

	    assign(T4, T2, T3);

	}
    }

    /**
     * Doubles this point in affine coordinates.
     * 
     * @return 2*<code>this</code> in affine coordinates
     */
    public Point multiplyBy2Affine() {
	PointGF2n p = (PointGF2n) this.getAffin();

	GF2nElement pX = p.mX;
	GF2nElement pY = p.mY;

	if (pX.isZero() || mZ.isZero()) {
	    return new PointGF2n((EllipticCurveGF2n) mE);
	}

	GF2nElement lambda = (GF2nElement) pX.invert();
	lambda = (GF2nElement) lambda.multiply(pY);
	lambda = (GF2nElement) lambda.add(pX);

	GF2nElement x = (GF2nElement) lambda.square().add(lambda);
	x = (GF2nElement) x.add(((EllipticCurveGF2n) mE).getA());

	GF2nElement y = (GF2nElement) lambda.add(createGF2nOneElement(mGF2n))
		.multiply(x);
	y = (GF2nElement) y.add(pX.square());

	return new PointGF2n(x, y, (EllipticCurveGF2n) mE);
    }

    /**
     * Subtracts point <tt>other</tt> from this point. When P = (x, y) then -P =
     * (x, x + y). So this method returns<br>
     * <tt>add(other.negate())</tt>
     * 
     * @param other
     *                another Point
     * @return <tt>this</tt> - <tt>other</tt>
     * @throws DifferentCurvesException
     *                 if <tt>this</tt> and <tt>other</tt> are not on the
     *                 same curve.
     */
    public Point subtract(Point other) throws DifferentCurvesException {
	PointGF2n result = new PointGF2n(this);
	result.subtractFromThis(other);
	return result;
    }

    /**
     * Subtracts point <tt>other</tt> from this point. When P = (x, y) then -P =
     * (x, x + y).
     * 
     * @param other
     *                another Point
     * @throws DifferentCurvesException
     *                 if <tt>this</tt> and <tt>other</tt> are not on the
     *                 same curve.
     */
    public void subtractFromThis(Point other) throws DifferentCurvesException {

	if (!(other instanceof PointGF2n)) {
	    throw new DifferentCurvesException(
		    "PointGF2n.subtractFromThis(Point P): other is not"
			    + " an instance of PointGF2n");
	}

	PointGF2n minusOther = (PointGF2n) other.negate();
	if (isZero()) {
	    assign(minusOther.mX, minusOther.mY, minusOther.mZ);
	} else {
	    addToThis(minusOther);
	}
    }

    /**
     * Returns the inverse of this point. When P = (x, y) then -P = (x, x + y).
     * 
     * @return -<tt>this</tt>
     */
    public Point negate() {
	PointGF2n result = new PointGF2n(this);
	result.negateThis();
	return result;
    }

    /**
     * Negates this PointGF2n.
     */
    public void negateThis() {
	if (!isZero()) {
	    GFElement tmp = mX.multiply(mZ);
	    mY = (GF2nElement) tmp.add(mY);
	}
    }

    // ////////////////////////////////////////////////////////////////////
    // Output
    // ////////////////////////////////////////////////////////////////////

    /**
     * Returns this point in affine, decompressed form as a byte array. The
     * first byte keeps the value 4, to indicate, that this point is stored in
     * an uncompressed format. The rest of the returned array is split in two
     * halves, the first holds the x-coordinate <tt>mX</tt> and the second
     * they-coordinate <tt>mY</tt>.
     * 
     * @return <tt>this</tt> as byte array
     */
    byte[] encodeUncompressed() {

	// the zero point is encoded as a single byte 0
	if (isZero()) {
	    return new byte[1];
	}

	int l = mDeg;
	final int dummy = l & 7;
	if (dummy != 0) {
	    l += 8 - dummy;
	}
	l >>>= 3;

	byte[] encoded = new byte[(l << 1) + 1];

	encoded[0] = 4;

	byte[] bX = getXAffin().toByteArray();
	byte[] bY = getYAffin().toByteArray();
	System.arraycopy(bX, 0, encoded, 1 + l - bX.length, bX.length);
	System.arraycopy(bY, 0, encoded, 1 + (l << 1) - bY.length, bY.length);

	return encoded;
    }

    /**
     * Returns this point in affine, compressed form as a byte array. The first
     * byte keeps the value 2 or 3, to indicate, that this point is stored in a
     * compressed format. The rest of the returned array is the x-coordinate
     * <tt>mX</tt>.
     * 
     * @return <tt>this</tt> as byte array
     */
    byte[] encodeCompressed() {

	// the zero point is encoded as a single byte 0
	if (isZero()) {
	    return new byte[1];
	}

	int l = mDeg;
	if ((mDeg & 7) != 0) {
	    l += 8 - (mDeg & 7);
	}
	l >>>= 3;

	byte[] encoded = new byte[l + 1];

	encoded[0] = 2;

	GFElement xAff = getXAffin();
	byte[] bX = xAff.toByteArray();
	System.arraycopy(bX, 0, encoded, 1, bX.length);

	if (!(xAff.isZero())) {
	    GFElement xInv = xAff.invert();
	    GFElement comp = xInv.multiply(getYAffin());

	    if (((GF2nElement) comp).testRightmostBit()) {
		encoded[0] |= 1;
	    }
	}

	return encoded;
    }

    /**
     * Returns this point in affine, hybrid form as a byte array. The first byte
     * keeps the value 6 or 7, to indicate, that this point is stored in a
     * hybrid format. The rest of the returned array is split in two halves, the
     * first holds the x-coordinate <tt>mX</tt> and the second they-coordinate
     * <tt>mY</tt>.
     * 
     * @return <tt>this</tt> as byte array
     */
    byte[] encodeHybrid() {

	// the zero point is encoded as a single byte 0
	if (isZero()) {
	    return new byte[1];
	}

	int l = mDeg;
	if ((l & 7) != 0) {
	    l += 8 - (l & 7);
	}
	l >>>= 3;

	byte[] encoded = new byte[(l << 1) + 1];

	encoded[0] = 6;

	GFElement xAff = getXAffin();
	GFElement yAff = getYAffin();
	byte[] bX = xAff.toByteArray();
	byte[] bY = yAff.toByteArray();
	System.arraycopy(bX, 0, encoded, 1 + l - bX.length, bX.length);
	System.arraycopy(bY, 0, encoded, 1 + (l << 1) - bY.length, bY.length);

	if (!(xAff.isZero())) {
	    GFElement xInv = xAff.invert();
	    GFElement comp = xInv.multiply(yAff);

	    if (((GF2nElement) comp).testRightmostBit()) {
		encoded[0] |= 1;
	    }
	}

	return encoded;
    }

    // ////////////////////////////////////////////////////////////////////
    // help functions
    // ////////////////////////////////////////////////////////////////////

    /**
     * Compute the y-coordinate from the given x-coordinate, the elliptic curve
     * mE, and the the least significant bit yMod2 of y. Let
     * <tt>g = x<sup>3</sup> + ax + b mod p</tt>. Then
     * <tt>y = sqrt(g) mod p</tt> if either
     * <ul>
     * <li>y is even and yMod2 = 0 or if</li>
     * <li>y is odd and yMod2 = 1.</li>
     * </ul>
     * Otherwise, <tt>y = p - sqrt(g) mod p</tt>.
     */
    private GF2nElement decompress(boolean yMod2, GF2nElement x) {

	// if x = 0, y' = 1 -> y = b^0,5
	// if x != 0 -> y = (z + z' + y')x (see further down)

	if (x.isZero()) {
	    return mB.squareRoot();
	}

	GFElement alpha, beta, tmp;
	GF2nElement z = null;

	// x^3 + a*x^2 + b

	// tmp = x^2
	tmp = x.square();

	// beta = (x^2)^(-1)
	beta = tmp.invert();

	// alpha = a*x^2
	alpha = tmp.multiply(mA);

	// tmp = x^3
	tmp.multiplyThisBy(x);

	// alpha = x^3 + a*x^2
	alpha.addToThis(tmp);

	// alpha = x^3 + a*x^2 + b
	alpha.addToThis(mB);

	// (x^2)^(-1)*(x^3 + a*x^2 + b)

	// beta = (x^3 + a*x^2 + b)*(x^-2)
	beta.multiplyThisBy(alpha);

	z = ((GF2nElement) beta).solveQuadraticEquation();

	if (z.testRightmostBit()) {
	    z.increaseThis();
	}

	// (z + z' + yMod2) * x
	if (yMod2) {
	    z.increaseThis();
	}

	z.multiplyThisBy(x);

	return z;
    }

    private void setGF2nFieldType() {
	isGF2nONBField = mGF2n instanceof GF2nONBField;
    }

    private GF2nElement createGF2nZeroElement(GF2nField gf2n) {
	if (isGF2nONBField) {
	    return GF2nONBElement.ZERO((GF2nONBField) gf2n);
	}
	return GF2nPolynomialElement.ZERO((GF2nPolynomialField) gf2n);
    }

    private GF2nElement createGF2nOneElement(GF2nField gf2n) {
	if (isGF2nONBField) {
	    return GF2nONBElement.ONE((GF2nONBField) gf2n);
	}
	return GF2nPolynomialElement.ONE((GF2nPolynomialField) gf2n);
    }

    private GF2nElement createRandomGF2nElement(GF2nField gf2n, Random rand) {
	if (isGF2nONBField) {
	    return new GF2nONBElement((GF2nONBField) gf2n, rand);
	}
	return new GF2nPolynomialElement((GF2nPolynomialField) gf2n, rand);
    }

    private GF2nElement createGF2nElement(byte[] value) {
	if (isGF2nONBField) {
	    return new GF2nONBElement((GF2nONBField) mGF2n, value);
	}
	return new GF2nPolynomialElement((GF2nPolynomialField) mGF2n, value);
    }

}
