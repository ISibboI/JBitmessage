/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.common.math.ellipticcurves;

import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.math.finitefields.GF2nElement;
import de.flexiprovider.common.math.finitefields.GF2nField;

/**
 * This class provides features for elliptic curves over finite fields with
 * characteristic 2 (GF(2<sup>n</sup>). The equation for such a curve is: <br>
 * <i>E</i>: y<sup>2</sup> + xy = x<sup>3</sup> + ax<sup>2</sup> + b.
 * <br>
 * The parameters a and b are stored in <tt>GF2nElement</tt>s <tt>mA</tt>
 * and <tt>mB</tt>.
 * 
 * @author Birgit Henhapl
 * @see EllipticCurve
 * @see Point
 */
public class EllipticCurveGF2n extends EllipticCurve {

    // /////////////////////////////////////////////////////////////////
    // Constructors
    // /////////////////////////////////////////////////////////////////

    /**
     * Constructs an elliptic curve E with the specified parameters <tt>a</tt>
     * and <tt>b</tt> in short Weierstrass normal form in projective
     * representation over the field with the specified characteristic
     * <tt>2^deg</tt>.
     * 
     * @param a
     *                curve parameter a
     * @param b
     *                curve parameter b
     * @param deg
     *                extension degree of the underlying field
     * @see GF2nElement
     */
    public EllipticCurveGF2n(GF2nElement a, GF2nElement b, int deg) {
	super(a, b, (FlexiBigInt.ONE).shiftLeft(deg));
    }

    /**
     * Constructs an elliptic curve E with the specified parameters <tt>a</tt>
     * and <tt>b</tt> in short Weierstrass normal form in projective
     * representation over the field with the specified size.
     * 
     * @param a
     *                curve parameter a
     * @param b
     *                curve parameter b
     * @param q
     *                size of the underlying field
     * @see GF2nElement
     */
    public EllipticCurveGF2n(GF2nElement a, GF2nElement b, FlexiBigInt q) {
	super(a, b, q);
    }

    /**
     * Constructs an elliptic curve E with the specified parameters <tt>a</tt>
     * and <tt>b</tt> in short Weierstrass normal form in projective
     * representation over the given field.
     * 
     * @param a
     *                curve parameter a
     * @param b
     *                curve parameter b
     * @param gf2n
     *                the underlying field
     * @see GF2nElement
     */
    public EllipticCurveGF2n(GF2nElement a, GF2nElement b, GF2nField gf2n) {
	super(a, b, (FlexiBigInt.ONE).shiftLeft(gf2n.getDegree()));
    }

    // ////////////////////////////////////////////////////////////////////
    // Output
    // ////////////////////////////////////////////////////////////////////

    /**
     * @return a human readable form of this elliptic curve
     */
    public String toString() {
	return "y<sup>2</sup> + xy = x<sup>3</sup> +ax<sup>2</sup> + b, where\n"
		+ "a = "
		+ mA.toString(16)
		+ ",\nb = "
		+ mB.toString(16)
		+ "\n field order = " + mQ.toString(16);
    }

}
