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
import de.flexiprovider.common.math.finitefields.GFPElement;

/**
 * This class holds elliptic curves over prime fields <i>GF (p)</i>. The
 * equation for such a curve is:
 * <p align=center>
 * <i>E: y<sup>2</sup> = x<sup>3</sup> + ax + b.</i>
 * </p>
 * a and b are stored in <tt>FlexiBigInt</tt> instances <tt>mA</tt> and
 * <tt>mB</tt>, respectively.
 * 
 * @author Birgit Henhapl
 * @see EllipticCurve
 */
public class EllipticCurveGFP extends EllipticCurve {

    // ////////////////////////////////////////////////////////////////////
    // Constructor
    // ////////////////////////////////////////////////////////////////////

    /**
     * Constructs an elliptic curve E with the specified parameters <tt>a</tt>
     * and <tt>b</tt> in short Weierstrass normal form in projective
     * representation over the prime field with the specified characteristic.
     * 
     * @param a
     *                curve parameter a
     * @param b
     *                curve parameter b
     * @param p
     *                characteristic of the underlying prime field
     * @see GFPElement
     */
    public EllipticCurveGFP(GFPElement a, GFPElement b, FlexiBigInt p) {
	super(a, b, p);
    }

    // ////////////////////////////////////////////////////////////////////
    // Output
    // ////////////////////////////////////////////////////////////////////

    /**
     * @return a human readable form of this elliptic curve
     */
    public final String toString() {
	return "y^2 = x^3 + ax + b, where\n" + "a = " + mA.toString(16)
		+ ",\nb = " + mB.toString(16) + "\n field order = "
		+ mQ.toString(16);
    }

}
