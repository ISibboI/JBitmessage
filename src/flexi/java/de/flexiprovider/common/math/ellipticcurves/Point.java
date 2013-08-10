package de.flexiprovider.common.math.ellipticcurves;

import de.flexiprovider.api.exceptions.InvalidParameterSpecException;
import de.flexiprovider.common.exceptions.DifferentCurvesException;
import de.flexiprovider.common.exceptions.InvalidFormatException;
import de.flexiprovider.common.exceptions.InvalidPointException;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.math.finitefields.GFElement;
import de.flexiprovider.ec.parameters.CurveParams;

/**
 * This abstract class implements points and their arithmetic on elliptic curves
 * over finite prime fields as well as over finite fields with characteristic 2.
 * There is a variety of methods for point multiplication. See the references
 * for complexity and details.
 * <P>
 * <table cellpadding="2" cellspacing="2" border="1" width="90% align="center"">
 * <tbody>
 * <tr>
 * <td valign="top">MvV97<br>
 * </td>
 * <td valign="top">A. J. Menezes, P. C. van Oorschot, and S. A. Vanstone.
 * Handbook of Applied Cryptography. CRC Press, Boca Raton, Florida, 1997.<br>
 * </td>
 * </tr>
 * <tr>
 * <td valign="top">LL94<br>
 * </td>
 * <td valign="top">C. H. Lim and P. J Lee. More flexible exponentiation with
 * precompu-tation. In Yvo G. Desmedt, editor, Advances in
 * Cryptology&nbsp;&nbsp; CRYP-TO&nbsp; 94, volume 839 of Lecture Notes in
 * Computer Science, pages 108 113. Springer-Verlag, August 1994.<br>
 * </td>
 * </tr>
 * <tr>
 * <td valign="top">YLL94<br>
 * </td>
 * <td valign="top">S.-M. Yen, C.-S. Laih, and A. Lenstra.
 * Multi-exponentiation. In IEE Proceedings - Computers and Digital Techniques,
 * volume 141, pages 325 326, 1994.<br>
 * </td>
 * </tr>
 * <tr>
 * <td valign="top">MOC97<br>
 * </td>
 * <td valign="top">Atsuko Miyaji, Takatoshi Ono, Henri Cohen. Efficient
 * elliptic curve exponentiation.<br>
 * </td>
 * </tr>
 * <tr>
 * <td valign="top">Moe01<br>
 * </td>
 * <td valign="top">Bodo Moeller. Algorithms for multi-exponentiation. In Serge
 * Vau-denay and Amr M. Youssef, editors, Selected Areas in Cryptography - SAC
 * 2001, pages 165 180. Springer-Verlag, 2001.<br>
 * </td>
 * </tr>
 * <tr>
 * <td valign="top">Moe04<br>
 * </td>
 * <td valign="top">Bodo Moeller. Fractional Windows Revisited:Improved
 * Signed-Digit Representations for Efficient Exponentiation.<br>
 * </td>
 * </tr>
 * <tr>
 * <td valign="top">OSST04<br>
 * </td>
 * <td valign="top">Katsuyuki Okeya, Katja Schmidt-Samoa, Christian Spahn,
 * Tsuyoshi Takagi. Signed Binary Representations Revisited.<br>
 * </td>
 * </tr>
 * <tr>
 * <td valign="top">DOT07<br>
 * </td>
 * <td valign="top">Erik Dahmen, Katsuyuki Okeya, Tsuyoshi Takagi. A new upper
 * bound for the minimal density of joint representations in elliptic curve
 * cryptosystems.<br>
 * </td>
 * </tr>
 * <tr>
 * <td valign="top">PRO03<br>
 * </td>
 * <td valign="top">John Proos. Joint Sparse Forms and Generating Zero Columns
 * when Combing.<br>
 * </td>
 * </tr>
 * </tbody> </table>
 * 
 * @author Birgit Henhapl
 * @see EllipticCurve
 * @see PointGFP
 * @see PointGF2n
 */
public abstract class Point {

    // /////////////////////////////////////////////////////////////
    // some constants
    // /////////////////////////////////////////////////////////////

    /**
     * The elliptic curve this point is on.
     * 
     * @see EllipticCurve
     */
    protected EllipticCurve mE;

    /**
     * Characteristic of underlying field.
     */
    protected FlexiBigInt mP;

    /**
     * Encoding type 'uncompressed'
     */
    public static final int ENCODING_TYPE_UNCOMPRESSED = 0;

    /**
     * Encoding type 'compressed'
     */
    public static final int ENCODING_TYPE_COMPRESSED = 1;

    /**
     * Encoding type 'hybrid'
     */
    public static final int ENCODING_TYPE_HYBRID = 2;

    /**
     * @return a copy of this Point
     */
    public abstract Object clone();

    /**
     * Compare this point with another object.
     * 
     * @param other
     *                the other object
     * @return the result of the comparison
     */
    public abstract boolean equals(Object other);

    /**
     * @return the hash code of this point
     */
    public abstract int hashCode();

    // ///////////////////////////////////////////////////////////
    // access
    // ///////////////////////////////////////////////////////////

    /**
     * @return the underlying elliptic curve
     */
    public final EllipticCurve getE() {
	return mE;
    }

    /**
     * @return the x-coordinate of this point
     */
    public abstract GFElement getX();

    /**
     * @return the y-coordinate of this point
     */
    public abstract GFElement getY();

    /**
     * @return the z-coordinate of this point
     */
    public abstract GFElement getZ();

    /**
     * @return the x-coordinate of this point in affine representation
     */
    public abstract GFElement getXAffin();

    /**
     * @return the y-coordinate of this point in affine representation
     */
    public abstract GFElement getYAffin();

    /**
     * Returns this point with affin coordinates.
     * 
     * @return <tt>this</tt>
     */
    public abstract Point getAffin();

    /**
     * Test whether this point is on curve E.
     * 
     * @return <tt>true</tt> if <tt>this</tt> == O or if (<tt>mX</tt>,
     *         <tt>mY</tt>) is on <tt>mE</tt><br>
     *         <tt>false</tt> if (<tt>mX</tt>, <tt>mY</tt>) is not on
     *         <tt>mE</tt>
     */
    public abstract boolean onCurve();

    /**
     * Tests, whether this point is at infinity.
     * 
     * @return <tt>true</tt> if <tt>this</tt> == O<br>
     *         <tt>false</tt> if <tt>this</tt> != O
     */
    public abstract boolean isZero();

    // /////////////////////////////////////////////////////////
    // comparison
    // ////////////////////////////////////////////////////////

    /**
     * Tests whether this point is the negative of other.
     * 
     * @param other
     *                point to compare this point with
     * @return <tt>true</tt> if <tt>this == -other</tt>, <tt>false</tt>
     *         otherwise.
     */
    public final boolean isNegativeOf(Point other) {
	return equals(other.negate());
    }

    // ////////////////////////////////////////////////////////////////////
    // arithmetic
    // ////////////////////////////////////////////////////////////////////

    /**
     * Adds to this point the point <tt>other</tt>.
     * 
     * @param other
     *                point to add to this point
     * @throws DifferentCurvesException
     *                 when <tt>other</tt> is defined over another curve
     * @return <tt>this</tt> + <tt>other</tt>
     */
    public abstract Point add(Point other) throws DifferentCurvesException;

    /**
     * Adds to this point the point <tt>other</tt>.
     * 
     * @param other
     *                point to add to this point
     * @throws DifferentCurvesException
     *                 when <tt>other</tt> is defined over another curve
     */
    public abstract void addToThis(Point other) throws DifferentCurvesException;

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
    public abstract Point addAffine(Point other)
	    throws DifferentCurvesException;

    /**
     * Subtracts the point <tt>other</tt> from this point.
     * 
     * @param other
     *                point to subtract from this point
     * @return <tt>this</tt> - <tt>other</tt>
     * @throws DifferentCurvesException
     *                 if <tt>other</tt> is defined over a different curve
     */
    public abstract Point subtract(Point other) throws DifferentCurvesException;

    /**
     * Subtracts the point <tt>other</tt> from this point.
     * 
     * @param other
     *                point to subtract from this point
     * @throws DifferentCurvesException
     *                 if <tt>other</tt> is defined over a different curve
     */
    public abstract void subtractFromThis(Point other)
	    throws DifferentCurvesException;

    /**
     * Doubles this point.
     * 
     * @return 2*<tt>this</tt>
     */
    public abstract Point multiplyBy2();

    /**
     * Doubles this point.
     */
    public abstract void multiplyThisBy2();

    /**
     * Doubles this point in affine coordinates.
     * 
     * @return 2*<code>this</code> in affine coordinates
     */
    public abstract Point multiplyBy2Affine();

    /**
     * @return the inverse of this point. returns -<tt>this</tt>
     */
    public abstract Point negate();

    /**
     * Additively invert this point.
     */
    public abstract void negateThis();

    // ////////////////////////////////////////////////////////////////////
    // help functions
    // ////////////////////////////////////////////////////////////////////

    /**
     * Encode this point into a byte array (octet string) using the specified
     * encoding format (one of {@link #ENCODING_TYPE_UNCOMPRESSED},
     * {@link #ENCODING_TYPE_COMPRESSED}, and {@link #ENCODING_TYPE_HYBRID}).
     * 
     * @param type
     *                the encoding format
     * @return the encoded point, or <tt>null</tt> if the encoding format is
     *         unknown.
     */
    public final byte[] EC2OSP(int type) {
	switch (type) {
	case ENCODING_TYPE_COMPRESSED:
	    return encodeCompressed();
	case ENCODING_TYPE_UNCOMPRESSED:
	    return encodeUncompressed();
	case ENCODING_TYPE_HYBRID:
	    return encodeHybrid();
	default:
	    return null;
	}
    }

    /**
     * Decode the encoded point given as byte array using the given EC domain
     * parameters.
     * 
     * @param encoded
     *                the encoded point
     * @param params
     *                the EC domain parameters
     * @return the decoded point
     * @throws InvalidPointException
     *                 if the point is encoded in hybrid format and the given
     *                 and the decoded y-coordinates don't match.
     * @throws InvalidFormatException
     *                 if the encoded point is given in an invalid encoding
     *                 format.
     * @throws InvalidParameterSpecException
     *                 if the parameters are defined neither over GF(2^n) nor
     *                 over GF(p).
     */
    public static Point OS2ECP(byte[] encoded, CurveParams params)
	    throws InvalidPointException, InvalidFormatException,
	    InvalidParameterSpecException {
	EllipticCurve mE = params.getE();

	Point mW;
	if (mE instanceof EllipticCurveGF2n) {
	    mW = new PointGF2n(encoded, (EllipticCurveGF2n) mE);
	} else if (mE instanceof EllipticCurveGFP) {
	    mW = new PointGFP(encoded, (EllipticCurveGFP) mE);
	} else {
	    throw new InvalidParameterSpecException(
		    "the parameters are defined neither over GF(p) nor over GF(2^n)");
	}

	return mW;
    }

    /**
     * Returns this point in affin, decompressed form as a byte array. The first
     * byte keeps the value 4, to indicate, that this point is stored in an
     * uncompressed format. The rest of the returned array is split in two
     * halves, the first holds the x-coordinate <tt>mX</tt> and the second
     * they-coordinate <tt>mY</tt>.
     * 
     * @return <tt>this</tt> as byte array
     */
    abstract byte[] encodeUncompressed();

    /**
     * Returns this point in affin, compressed form as a byte array. The first
     * byte keeps the value 2 or 3, to indicate, that this point is stored in a
     * compressed format. The rest of the returned array is the x-coordinate
     * <tt>mX</tt>.
     * 
     * @return <tt>this</tt> as byte array
     */
    abstract byte[] encodeCompressed();

    /**
     * Returns this point in affin, hybrid form as a byte array. The first byte
     * keeps the value 6 or 7, to indicate, that this point is stored in a
     * hybrid format. The rest of the returned array is split in two halves, the
     * first holds the x-coordinate <tt>mX</tt> and the second they-coordinate
     * <tt>mY</tt>.
     * 
     * @return <tt>this</tt> as byte array
     */
    abstract byte[] encodeHybrid();

}
