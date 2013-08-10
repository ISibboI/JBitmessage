package de.flexiprovider.common.math.ellipticcurves;

//import java.math.BigInteger;

import java.util.Random;

import de.flexiprovider.api.Registry;
import de.flexiprovider.common.exceptions.DifferentCurvesException;
import de.flexiprovider.common.exceptions.DifferentFieldsException;
import de.flexiprovider.common.exceptions.InvalidFormatException;
import de.flexiprovider.common.exceptions.InvalidPointException;
import de.flexiprovider.common.exceptions.NoQuadraticResidueException;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.math.IntegerFunctions;
import de.flexiprovider.common.math.finitefields.GFElement;
import de.flexiprovider.common.math.finitefields.GFPElement;
import de.flexiprovider.common.util.FlexiBigIntUtils;

/**
 * This class implements points and their arithmetic on elliptic curves over
 * finite prime fields (<i>GF(p)</i>). For more information on the arithmetic
 * see for example <a href =
 * http://www.certicom.com/research/online.html>Certicom online- tutorial</a>.
 * 
 * @author Birgit Henhapl
 * @see EllipticCurveGFP
 * @see PointGFP
 */
public class PointGFP extends Point {

    /**
     * curve parameter a
     */
    private GFPElement mA;

    /**
     * curve parameter b
     */
    private GFPElement mB;

    /**
     * x-coordinate of this point
     */
    private GFPElement mX;

    /**
     * y-coordinate of this point
     */
    private GFPElement mY;

    /**
     * z-coordinate of this point
     */
    private GFPElement mZ;

    /**
     * holds z<sup>2</sup> of this point
     */
    private GFPElement mZ2;

    /**
     * holds z<sup>3</sup> of this point
     */
    private GFPElement mZ3;

    /**
     * holds a * z<sup>3</sup> of this point
     */
    private GFPElement mAZ4;

    // /////////////////////////////////////////////////////////////
    // constructors
    // /////////////////////////////////////////////////////////////

    /**
     * Construct the point at infinity on the specified elliptic curve.
     * 
     * @param E
     *                EllipticCurveGFP is the elliptic curve this point lies on
     */
    public PointGFP(EllipticCurveGFP E) {
	mE = E;
	mP = E.getQ();
	mA = (GFPElement) E.getA();
	mB = (GFPElement) E.getB();
	assignZero();
    }

    /**
     * Construct a random point on the specified elliptic curve using the given
     * source of randomness.
     * 
     * @param E
     *                EllipticCurveGFP is the elliptic curve this point lies on
     * @param rand
     *                the source of randomness
     */
    public PointGFP(EllipticCurveGFP E, Random rand) {

	mE = E;
	mP = E.getQ();
	mA = (GFPElement) E.getA();
	mB = (GFPElement) E.getB();

	// find random point
	final GFPElement minusOne = new GFPElement(FlexiBigInt.ONE.negate(), E
		.getQ());
	mY = minusOne;
	GFElement y2 = null;
	GFElement x = null;

	while (mY.equals(minusOne)) {
	    FlexiBigInt value = new FlexiBigInt(mP.bitLength(), Registry
		    .getSecureRandom());
	    mX = new GFPElement(value, mP);
	    y2 = mA.multiply(mX);
	    x = mX.multiply(mX);
	    x.multiplyThisBy(mX);
	    y2.addToThis(x.add(mB));
	    try {
		value = IntegerFunctions.ressol(y2.toFlexiBigInt(), mP);
		mY = new GFPElement(value, mP);
	    } catch (NoQuadraticResidueException NQRExc) {
		mY = minusOne;
	    }
	}
	mZ = GFPElement.ONE(mP);
	mZ2 = GFPElement.ONE(mP);
	mZ3 = GFPElement.ONE(mP);
	mAZ4 = mA;
    }

    /**
     * Constructs point with specified parameters. This method throws an
     * <tt>InvalidPointException</tt>, if (<tt>x</tt>, <tt>y</tt>,
     * <tt>z</tt>) is not on curve <tt>E</tt>.
     * 
     * @param x
     *                x-coordinate
     * @param y
     *                y-coordinate
     * @param E
     *                EllipticCurveGFP is the elliptic curve this point lies on
     * @throws InvalidPointException
     *                 if the specified point is not on the curve.
     * @throws DifferentFieldsException
     *                 if <tt>x</tt> and <tt>y</tt> are defined over
     *                 different fields.
     */
    public PointGFP(GFPElement x, GFPElement y, EllipticCurveGFP E)
	    throws InvalidPointException, DifferentFieldsException {

	mE = E;
	mP = E.getQ();
	mA = (GFPElement) E.getA();
	mB = (GFPElement) E.getB();

	mX = (GFPElement) x.clone();
	mY = (GFPElement) y.clone();
	mZ = GFPElement.ONE(mP);
	mZ2 = null;
	mZ3 = null;
	mAZ4 = null;
    }

    /**
     * Constructs point with specified parameters. This method throws an
     * <tt>InvalidPointException</tt>, if (<tt>x</tt>, <tt>y</tt>,
     * <tt>z</tt>) is not on curve <tt>E</tt>.
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
    public PointGFP(GFPElement x, GFPElement y, GFPElement z, EllipticCurveGFP E)
	    throws InvalidPointException, DifferentFieldsException {

	mE = E;
	mP = E.getQ();
	mA = (GFPElement) E.getA();
	mB = (GFPElement) E.getB();

	mX = x;
	mY = y;
	mZ = z;
	mZ2 = null;
	mZ3 = null;
	mAZ4 = null;
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
    public PointGFP(byte[] encoded, EllipticCurveGFP E)
	    throws InvalidPointException, InvalidFormatException {

	mE = E;
	mP = E.getQ();
	mA = (GFPElement) E.getA();
	mB = (GFPElement) E.getB();

	// the zero point is encoded as a single byte 0
	if (encoded.length == 1 && encoded[0] == 0) {
	    assignZero();
	    return;
	}

	// the first OCTET pc indicates the form the point is represented in:
	// if pc = 2, the indicating bit is not set (point = pc | x)
	// if pc = 3, the indicating bit is set (point = pc | x)
	// if pc = 4, x and y are given: (point = pc | x | y), |x| = |y| =
	// (|point| - 1) / 2)
	// if pc = 6, x and y are given and the indicating bit is not set:
	// (point = pc | x | y), |x| = |y| = (|point| - 1) / 2)
	// if pc = 7, x and y are given and the indicating bit is set: (point =
	// pc | x | y), |x| = |y| = (|point| - 1) / 2)

	byte[] bX, bY;
	GFPElement x, y, z;

	final byte pc = encoded[0];

	switch (pc) {

	case 2:
	case 3:
	    // compressed form
	    bX = new byte[encoded.length - 1];
	    System.arraycopy(encoded, 1, bX, 0, bX.length);
	    x = new GFPElement(new FlexiBigInt(1, bX), mP);
	    boolean yMod2 = (pc & 1) == 1;
	    y = decompress(yMod2, x);
	    break;

	case 4:
	    // uncompressed form
	    int l = (encoded.length - 1) >> 1;
	    bX = new byte[l];
	    bY = new byte[l];
	    System.arraycopy(encoded, 1, bX, 0, l);
	    System.arraycopy(encoded, 1 + l, bY, 0, l);
	    x = new GFPElement(new FlexiBigInt(1, bX), mP);
	    y = new GFPElement(new FlexiBigInt(1, bY), mP);
	    break;

	case 6:
	case 7:
	    // hybrid form
	    l = (encoded.length - 1) >> 1;
	    bX = new byte[l];
	    bY = new byte[l];
	    System.arraycopy(encoded, 1, bX, 0, l);
	    System.arraycopy(encoded, 1 + l, bY, 0, l);
	    x = new GFPElement(new FlexiBigInt(1, bX), mP);
	    y = new GFPElement(new FlexiBigInt(1, bY), mP);
	    yMod2 = (pc & 0x01) == 1;
	    if (!(decompress(yMod2, x).equals(y))) {
		throw new InvalidPointException();
	    }
	    break;

	default:
	    throw new InvalidFormatException(pc);
	}

	z = GFPElement.ONE(mP);

	assign(x, y, z);
    }

    /**
     * Copy constructor.
     * 
     * @param other
     *                point to copy
     */
    public PointGFP(PointGFP other) {
	mE = other.mE;
	mP = other.mP;
	mA = other.mA;
	mB = other.mB;

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
	mX = GFPElement.ONE(mP);
	mY = GFPElement.ONE(mP);
	mZ = GFPElement.ZERO(mP);
	mZ2 = null;
	mZ3 = null;
	mAZ4 = null;
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
    private void assign(GFPElement x, GFPElement y, GFPElement z) {
	mX = x;
	mY = y;
	mZ = z;
	mZ2 = null;
	mZ3 = null;
	mAZ4 = null;
    }

    /**
     * Assigns to this point the x-, y- and z-coordinates of the given other
     * point (by copying the coordinates).
     * 
     * @param other
     *                the other point
     */
    private void assign(PointGFP other) {
	mX = (GFPElement) other.mX.clone();
	mY = (GFPElement) other.mY.clone();
	mZ = (GFPElement) other.mZ.clone();
	mZ2 = null;
	mZ3 = null;
	mAZ4 = null;
    }

    /**
     * @return a clone of this point
     */
    public Object clone() {
	return new PointGFP(this);
    }

    /**
     * Tests whether this Point is equal to other. The points are equal, if <br>
     * <tt><tt>mX</tt>*<tt>other.mZ</tt><sup>2</sup> ==
     * <tt>other.mX</tt>*<tt>mZ</tt><sup>2</sup></tt>
     * and <tt><tt>mY</tt>*<tt>other.mZ</tt><sup>3</sup>
     * <tt>other.mY</tt>*<tt>mZ</tt><sup>3</sup></tt>.
     * 
     * @param other
     *                Point to compare this Point with
     * @return <tt>(<tt>mX</tt>*<tt>other.mZ</tt><sup>2</sup> ==
     * <tt>other.mX</tt>*<tt>mZ</tt><sup>2</sup>) <tt>AND</tt>
     * (<tt>mY</tt>*<tt>other.mZ</tt><sup>3</sup>
     * <tt>other.mY</tt>*<tt>mZ</tt><sup>3</sup>)</tt>
     */
    public boolean equals(Object other) {

	// Guard against other==null or being of an unsuitable type:
	if (other == null || !(other instanceof PointGFP)) {
	    return false;
	}

	PointGFP otherPoint = (PointGFP) other;

	if (!mE.equals(otherPoint.mE)) {
	    return false;
	}

	if (isZero() && otherPoint.isZero()) {
	    return true;
	}

	GFElement oX = (GFElement) otherPoint.mX.clone();
	GFElement oY = (GFElement) otherPoint.mY.clone();
	GFElement oZ = (GFElement) otherPoint.mZ.clone();

	if (mZ.isOne() && oZ.isOne()) {
	    if (!(oX.equals(mX) && oY.equals(mY))) {
		return false;
	    }
	}

	if (!mZ.isOne()) {
	    GFElement z = (GFElement) mZ.clone();
	    GFElement z2 = z.multiply(z);
	    GFElement z3 = z2.multiply(z);

	    oX.multiplyThisBy(z2);
	    oY.multiplyThisBy(z3);
	}

	GFElement x = (GFElement) mX.clone();
	GFElement y = (GFElement) mY.clone();

	if (!oZ.isOne()) {
	    GFElement oZ2 = oZ.multiply(oZ);
	    GFElement oZ3 = oZ2.multiply(oZ);

	    x.multiplyThisBy(oZ2);
	    y.multiplyThisBy(oZ3);
	}

	return oX.equals(x) && oY.equals(y);
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
	if (isZero()) {
	    return "(0, 0)";
	}
	return "(" + getXAffin().toString() + ",\n " + getYAffin().toString()
		+ ")";
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

	// TODO the zero point has no affine coordinates
	if (isZero()) {
	    return GFPElement.ZERO(mP);
	}

	// return mX*mZ^-2
	if (mZ2 == null) {
	    mZ2 = (GFPElement) mZ.multiply(mZ);
	}

	return mX.multiply(mZ2.invert());
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

	// TODO the zero point has no affine coordinates
	if (isZero()) {
	    return GFPElement.ZERO(mP);
	}
	// return mY*mZ^-3
	if (mZ3 == null) {
	    mZ3 = (GFPElement) mZ.multiply(mZ).multiply(mZ);
	}

	return mY.multiply(mZ3.invert());
    }

    /**
     * Returns this point with affine coordinates.
     * 
     * @return <tt>this</tt>
     */
    public Point getAffin() {
	if (!(mZ.isOne()) && !(mZ.isZero())) {
	    GFElement z = mZ.invert();
	    GFElement z2 = z.multiply(z);
	    z.multiplyThisBy(z2);
	    GFElement x = mX.multiply(z2);
	    GFElement y = mY.multiply(z);
	    return new PointGFP((GFPElement) x, (GFPElement) y,
		    (EllipticCurveGFP) mE);
	}
	return this;
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
     * @see EllipticCurveGFP
     */
    public boolean onCurve() {
	// The point at infinity is always on the curve:
	if (isZero()) {
	    return true;
	}

	// y^2
	final GFElement y2 = mY.multiply(mY);
	// x^3
	final GFElement x3 = mX.multiply(mX).multiply(mX);

	/*
	 * If the jacobian coordinate Z is 1, we can use the simpler affine
	 * equation for E:
	 */
	if (mZ.isOne()) {
	    // Compare y^2 to (x^3 + ax + b):
	    final GFElement ax = mA.multiply(mX); // a*x
	    return y2.equals(x3.add(ax).add(mB));
	}
	/*
	 * Z != 1, we have to use the jacobian equation for E:
	 */
	// Update mZ* fields if necessary:
	if (mZ2 == null) {
	    mZ2 = (GFPElement) mZ.multiply(mZ); // z^2
	}
	if (mZ3 == null) {
	    mZ3 = (GFPElement) mZ2.multiply(mZ); // z^3
	}
	if (mAZ4 == null) {
	    mAZ4 = (GFPElement) mZ3.multiply(mZ).multiply(mA); // a*z^4
	}

	// Compare y^2 to (x^3 + axz^4 + bz^6):
	final GFElement aXZ4 = mAZ4.multiply(mX); // a*x*z^4
	final GFElement bZ6 = mB.multiply(mZ3).multiply(mZ3); // b*z^6
	return y2.equals(x3.add(aXZ4).add(bZ6));
    }

    /**
     * @return <tt>true</tt> if this point is the point at infinity,
     *         <tt>false</tt> otherwise.
     */
    public boolean isZero() {
	return mX.isOne() && mY.isOne() && mZ.isZero();
    }

    // ////////////////////////////////////////////////////////////////////
    // arithmetic
    // ////////////////////////////////////////////////////////////////////

    /**
     * Adds to this point <tt>other</tt>. The formula is:<br>
     * X<sub>3</sub> = -H<sup>3</sup> - 2U<sub>1</sub>H<sup>2</sup> + r<sup>2</sup><br>
     * Y<sub>3</sub> = -S<sub>1</sub>H<sup>3</sup> + r*(U<sub>1</sub>H<sup>2</sup> -
     * X<sub>3</sub><br>
     * Z<sub>3</sub> = Z<sub>1</sub>Z<sub>2</sub>H<br>
     * Z<sub>3</sub><sup>2</sup> = Z<sub>3</sub><sup>2</sup><br>
     * Z<sub>3</sub><sup>3</sup> = Z<sub>3</sub><sup>3</sup><br>
     * with<br>
     * U<sub>1</sub> = X<sub>1</sub>Z<sub>2</sub><sup>2</sup><br>
     * U<sub>2</sub> = X<sub>2</sub>Z<sub>1</sub><sup>2</sup><br>
     * S<sub>1</sub> = Y<sub>1</sub>Z<sub>2</sub><sup>3</sup><br>
     * S<sub>2</sub> = Y<sub>2</sub>Z<sub>1</sub><sup>3</sup><br>
     * H = U<sub>2</sub> - U<sub>1</sub><br>
     * r = S<sub>2</sub> - S<sub>1</sub><br>
     * 
     * @param other
     *                point to add to this point
     * @return <tt>this + other</tt>
     */
    public Point add(Point other) {
	PointGFP result = new PointGFP(this);
	result.addToThis(other);
	return result;
    }

    /**
     * Adds to this point <tt>other</tt>. The formula is:<br>
     * X<sub>3</sub> = -H<sup>3</sup> - 2U<sub>1</sub>H<sup>2</sup> + r<sup>2</sup><br>
     * Y<sub>3</sub> = -S<sub>1</sub>H<sup>3</sup> + r*(U<sub>1</sub>H<sup>2</sup> -
     * X<sub>3</sub><br>
     * Z<sub>3</sub> = Z<sub>1</sub>Z<sub>2</sub>H<br>
     * Z<sub>3</sub><sup>2</sup> = Z<sub>3</sub><sup>2</sup><br>
     * Z<sub>3</sub><sup>3</sup> = Z<sub>3</sub><sup>3</sup><br>
     * with<br>
     * U<sub>1</sub> = X<sub>1</sub>Z<sub>2</sub><sup>2</sup><br>
     * U<sub>2</sub> = X<sub>2</sub>Z<sub>1</sub><sup>2</sup><br>
     * S<sub>1</sub> = Y<sub>1</sub>Z<sub>2</sub><sup>3</sup><br>
     * S<sub>2</sub> = Y<sub>2</sub>Z<sub>1</sub><sup>3</sup><br>
     * H = U<sub>2</sub> - U<sub>1</sub><br>
     * r = S<sub>2</sub> - S<sub>1</sub><br>
     * 
     * @param other
     *                point to add to this point
     */
    public void addToThis(Point other) {

	if (!(other instanceof PointGFP)) {
	    throw new DifferentCurvesException();
	}

	PointGFP otherPoint = (PointGFP) other;

	if (isZero()) {
	    assign(otherPoint);
	    return;
	}

	if (other.isZero()) {
	    return;
	}

	GFElement oX = otherPoint.mX;
	GFElement oY = otherPoint.mY;
	GFElement oZ = otherPoint.mZ;
	GFElement oZ2 = otherPoint.mZ2;
	GFElement oZ3 = otherPoint.mZ3;

	GFElement U1 = null;
	GFElement U2 = null;
	GFElement S1 = null;
	GFElement S2 = null;

	if (oZ.isOne()) {

	    // U_1 = X_1*Z_22
	    //
	    U1 = mX;

	    // S_1 = Y_1*Z_23
	    //
	    S1 = mY;
	} else {

	    if (oZ2 == null || oZ3 == null) {
		oZ2 = oZ.multiply(oZ);
		oZ3 = oZ2.multiply(oZ);
	    }

	    // U_1 = X_1*Z_22
	    //
	    U1 = mX.multiply(oZ2);

	    // S_1 = Y_1*Z_23
	    //
	    S1 = mY.multiply(oZ3);

	}

	if (mZ.isOne()) {

	    // U_2 = X_2*Z_12
	    //
	    U2 = oX;

	    // S_2 = Y_2*Z_13
	    //
	    S2 = oY;
	} else {

	    if (mZ2 == null || mZ3 == null) {
		mZ2 = (GFPElement) mZ.multiply(mZ);
		mZ3 = (GFPElement) mZ2.multiply(mZ);
	    }

	    // U_2 = X_2*Z_12
	    //
	    U2 = oX.multiply(mZ2);

	    // S_2 = Y_2*Z_13
	    //
	    S2 = oY.multiply(mZ3);

	}

	// H = U2 - U1
	//
	GFElement H = U2.subtract(U1);

	// 3 = S2 - S1
	//
	GFElement r = S2.subtract(S1);

	if (H.isZero()) {
	    if (r.isZero()) {
		multiplyThisBy2();
		return;
	    }
	    assignZero();
	    return;
	}

	// U2 = H^2
	//
	U2 = H.multiply(H);

	// S2 = H^3
	//
	S2 = U2.multiply(H);

	// U2 = U1H^2
	//
	U2.multiplyThisBy(U1);

	// x = r^2 - S2 - 2U2
	//
	GFElement x = r.multiply(r).subtract(S2).subtract(U2.add(U2));

	// y = r(U2 - x) -S1S2
	//
	GFElement z = S1.multiply(S2);

	GFElement y = r.multiply(U2.subtract(x)).subtract(z);

	// z = Z1Z2H
	//
	if (mZ.isOne()) {
	    if (!oZ.isOne()) {
		z = oZ.multiply(H);

	    } else {
		z = H;

	    }
	} else if (!oZ.isOne()) {
	    U1 = mZ.multiply(oZ);

	    z = U1.multiply(H);

	} else {
	    z = mZ.multiply(H);

	}

	assign((GFPElement) x, (GFPElement) y, (GFPElement) z);
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

	PointGFP p = (PointGFP) this.getAffin();
	PointGFP o = (PointGFP) other.getAffin();
	if (this.isZero()) {
	    return new PointGFP(o);
	}

	if (other.isZero()) {
	    return new PointGFP(p);
	}

	GFPElement oX = o.mX;
	GFPElement oY = o.mY;
	GFPElement pX = p.mX;
	GFPElement pY = p.mY;

	FlexiBigInt boX = oX.toFlexiBigInt();
	FlexiBigInt boY = oY.toFlexiBigInt();
	FlexiBigInt bpX = pX.toFlexiBigInt();
	FlexiBigInt bpY = pY.toFlexiBigInt();

	// P == other -> double(P)
	if ((pX == oX) && (pY == oY)) {
	    return p.multiplyBy2Affine();
	}
	FlexiBigInt lambda = (boX.subtract(bpX)).modInverse(mP);
	lambda = lambda.multiply(boY.subtract(bpY)).mod(mP);

	FlexiBigInt x = lambda.multiply(lambda).mod(mP);
	x = x.subtract(bpX).subtract(boX);
	x = x.mod(mP);

	FlexiBigInt y = bpX.subtract(x);
	y = y.multiply(lambda);
	y = y.subtract(bpY).mod(mP);

	GFPElement gfpx = new GFPElement(x, mP);
	GFPElement gfpy = new GFPElement(y, mP);
	try {
	    return new PointGFP(gfpx, gfpy, (EllipticCurveGFP) mE);
	} catch (InvalidPointException IPExc) {
	    throw new RuntimeException("InvalidPointException: "
		    + IPExc.getMessage());
	}
    }

    /**
     * Subtracts point <tt>other</tt> from this point.
     * 
     * @param other
     *                another Point
     * @return <tt>this</tt> - <tt>other</tt>
     */
    public Point subtract(Point other) {
	PointGFP result = new PointGFP(this);
	result.subtractFromThis(other);
	return result;
    }

    /**
     * Subtracts point <tt>other</tt> from this point.
     * 
     * @param other
     *                another Point
     */
    public void subtractFromThis(Point other) {

	if (!(other instanceof PointGFP)) {
	    throw new DifferentCurvesException();
	}

	PointGFP minusOther = (PointGFP) other.negate();

	if (isZero()) {
	    assign(minusOther.mX, minusOther.mY, minusOther.mZ);
	} else {
	    addToThis(minusOther);
	}
    }

    /**
     * Returns the inverse of this point.
     * 
     * @return -<tt>this</tt>
     */
    public Point negate() {
	PointGFP result = new PointGFP(this);
	result.negateThis();
	return result;
    }

    /**
     * Returns the inverse of this point.
     */
    public void negateThis() {
	if (!isZero()) {
	    // y = -mY mod mP
	    FlexiBigInt y = mP.add(mY.toFlexiBigInt().negate());
	    mY = new GFPElement(y, mP);
	}
    }

    /**
     * Returns 2*<tt>this</tt>. The formula is:<br>
     * X<sub>2</sub> = T<br>
     * Y<sub>2</sub> = 8Y<sup>4</sup> + M(S - T)<br>
     * Z<sub>2</sub> = 2YZ<br>
     * Z<sub>2</sub><sup>2</sup> = Z<sub>2</sub><sup>2</sup><br>
     * Z<sub>2</sub><sup>3</sup> = Z<sub>2</sub><sup>3</sup><br>
     * with<br>
     * S = 4XY<sup>2</sup><br>
     * M = 3X<sup>2</sup> + a(Z<sup>2</sup>)<sup>2</sup><br>
     * T = -2S + M<sup>2</sup>
     * 
     * @return 2*<tt>this</tt>
     */
    public Point multiplyBy2() {
	PointGFP result = new PointGFP(this);
	result.multiplyThisBy2();
	return result;
    }

    /**
     * This = 2*<tt>this</tt>. The formula is:<br>
     * X<sub>2</sub> = -2S + M<sup>2</sup><br>
     * Y<sub>2</sub> = M(S - X<sub>2</sub>) - T<br>
     * Z<sub>2</sub> = 2YZ<br>
     * Z<sub>2</sub><sup>2</sup> = Z<sub>2</sub><sup>2</sup><br>
     * Z<sub>2</sub><sup>3</sup> = Z<sub>2</sub><sup>3</sup><br>
     * with<br>
     * S = 4XY<sup>2</sup><br>
     * M = 3X<sup>2</sup> + aZ<sup>4</sup><br>
     * T = 8Y<sup>4</sup>
     */
    public void multiplyThisBy2() {

	if (isZero()) {
	    assignZero();
	    return;
	}
	if (mY.isZero()) {
	    assignZero();
	    return;
	}

	// z = Y^2
	GFElement z = mY.multiply(mY);

	// S = 4XY^2
	GFElement S = mX.multiply(z);

	GFElement x = S.add(S);
	S = x.add(x);

	// M = 3X^2 + a(Z^2)^2
	//
	if (mAZ4 == null) {
	    if (mZ.isOne()) {
		mAZ4 = (GFPElement) mA.clone();
	    } else {
		if (mZ2 == null) {
		    mZ2 = (GFPElement) mZ.multiply(mZ);

		}
		x = mZ2.multiply(mZ2);
		mAZ4 = (GFPElement) mA.multiply(x);

	    }
	}
	GFElement y = mX.multiply(mX);

	GFElement M = y.add(y).add(y).add(mAZ4); // 3X^2+aZ^4
	// T = x = -2S + M^2
	//
	x = M.multiply(M).subtract(S.add(S));

	// y = -8Y^4 + M(S - T)
	//
	y = z.multiply(z);

	GFElement U = y.add(y); // 2Y^4
	z = U.add(U);
	U = z.add(z); // 8Y^4
	y = M.multiply(S.subtract(x)).subtract(U);

	// z = 2YZ;
	//
	if (!mZ.isOne()) {
	    z = mY.multiply(mZ);

	} else {
	    z = mY;
	}
	z = z.add(z);

	assign((GFPElement) x, (GFPElement) y, (GFPElement) z);
    }

    /**
     * Doubles this point in affine coordinates.
     * 
     * @return 2*<code>this</code> in affine coordinates
     */
    public Point multiplyBy2Affine() {

	if (this.isZero()) {
	    return new PointGFP((EllipticCurveGFP) this.mE);
	}

	if (this.mY.equals(FlexiBigInt.ZERO)) {
	    return new PointGFP((EllipticCurveGFP) mE);
	}

	PointGFP p = (PointGFP) this.getAffin();

	FlexiBigInt pX = p.mX.toFlexiBigInt();
	FlexiBigInt pY = p.mY.toFlexiBigInt();
	FlexiBigInt lambda, x, y, tmp;

	tmp = pY.add(pY).modInverse(mP);
	lambda = pX.multiply(pX).mod(mP);
	lambda = lambda
		.multiply(new FlexiBigInt(java.lang.Integer.toString(3))).mod(
			mP);
	lambda = lambda.add(mA.toFlexiBigInt());
	lambda = lambda.multiply(tmp).mod(mP);

	x = lambda.multiply(lambda).mod(mP);
	x = x.subtract(pX.add(pX)).mod(mP);

	y = pX.subtract(x);
	y = lambda.multiply(y);
	y = y.subtract(pY).mod(mP);

	GFPElement gfpx = new GFPElement(x, mP);
	GFPElement gfpy = new GFPElement(y, mP);
	return new PointGFP(gfpx, gfpy, (EllipticCurveGFP) p.mE);
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

	int l = mP.bitLength();
	final int dummy = l & 7;
	if (dummy != 0) {
	    l += 8 - dummy;
	}
	l >>>= 3;

	byte[] encoded = new byte[(l << 1) + 1];

	encoded[0] = 4;

	FlexiBigInt x = getXAffin().toFlexiBigInt();
	FlexiBigInt y = getYAffin().toFlexiBigInt();
	byte[] bX = FlexiBigIntUtils.toMinimalByteArray(x);
	byte[] bY = FlexiBigIntUtils.toMinimalByteArray(y);
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

	int l = mP.bitLength();
	int dummy = l & 7;
	if (dummy != 0) {
	    l += 8 - dummy;
	}
	l >>>= 3;

	byte[] encoded = new byte[l + 1];

	encoded[0] = 2;

	FlexiBigInt x = getXAffin().toFlexiBigInt();
	byte[] bX = FlexiBigIntUtils.toMinimalByteArray(x);
	System.arraycopy(bX, 0, encoded, 1 + l - bX.length, bX.length);

	FlexiBigInt y = getYAffin().toFlexiBigInt();
	if (y.testBit(0)) {
	    encoded[0] |= 1;
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

	int l = mP.bitLength();
	final int dummy = l & 7;
	if (dummy != 0) {
	    l += 8 - dummy;
	}
	l >>>= 3;

	byte[] encoded = new byte[(l << 1) + 1];

	encoded[0] = 6;

	FlexiBigInt x = getXAffin().toFlexiBigInt();
	FlexiBigInt y = getYAffin().toFlexiBigInt();
	byte[] bX = FlexiBigIntUtils.toMinimalByteArray(x);
	byte[] bY = FlexiBigIntUtils.toMinimalByteArray(y);
	System.arraycopy(bX, 0, encoded, 1 + l - bX.length, bX.length);
	System.arraycopy(bY, 0, encoded, 1 + (l << 1) - bY.length, bY.length);

	if (y.testBit(0)) {
	    encoded[0] |= 1;
	}

	return encoded;
    }

    // ////////////////////////////////////////////////////////////////////
    // help functions
    // ////////////////////////////////////////////////////////////////////

    /**
     * Computes the y-coordinate from the given x-coordinate, the elliptic curve
     * mE and the least significant bit yMod2 of y. Let g = x<sup>3</sup> + ax +
     * b mod p and z = sqrt(g) mod p. Then, y = z if either<br>
     * y is even and yMod2 = 0 or<br>
     * y is odd and yMod2 = 1.<br>
     * Otherwise, y = p - z.
     */
    private GFPElement decompress(boolean yMod2, GFElement x)
	    throws InvalidPointException {

	// compute g = x^3 + ax + b mod p
	FlexiBigInt xVal = x.toFlexiBigInt();
	// x3 = x^3
	FlexiBigInt x3 = xVal.multiply(xVal).multiply(xVal);
	FlexiBigInt g = mA.toFlexiBigInt().multiply(xVal);
	g = g.add(x3);
	g = g.add(mB.toFlexiBigInt());
	g = g.mod(mP);

	FlexiBigInt z;
	try {
	    // compute z = sqrt(g) mod p
	    z = IntegerFunctions.ressol(g, mP);
	} catch (NoQuadraticResidueException NQRExc) {
	    throw new InvalidPointException("NoQuadraticResidueException: "
		    + NQRExc.getMessage());
	}

	// if lowest bit of z and yMod2 are not equal, compute z = p - z
	boolean zMod2 = z.testBit(0);
	if ((zMod2 && !yMod2) || (!zMod2 && yMod2)) {
	    z = mP.subtract(z);
	}

	return new GFPElement(z, mP);
    }

}
