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
import de.flexiprovider.common.math.finitefields.GFElement;

/**
 * This class is the top-interface for elliptic curves over finite fields.
 * Implemented are those over prime fields <tt>GF(p)</tt> ({@link EllipticCurveGFP})
 * as well as over characteristic 2 fields <tt>GF(2<sup>n</sup>)</tt>) ({@link EllipticCurveGF2n}).
 * <p>
 * This class stores the size of the underlying field as a {@link FlexiBigInt}
 * <tt>mQ = p</tt> or <tt>mQ = 2<sup>n</sup></tt>. The curve parameters
 * <tt>a</tt> and <tt>b</tt> are stored as instances of {@link GFElement}.
 * 
 * @author Birgit Henhapl
 * @author Martin Döring
 * @see EllipticCurveGFP
 * @see EllipticCurveGF2n
 * @see GFElement
 */
public abstract class EllipticCurve {

    /**
     * size of the underlying field
     */
    protected FlexiBigInt mQ;

    /**
     * curve parameter a
     */
    protected GFElement mA;

    /**
     * curve parameter b
     */
    protected GFElement mB;

    // /////////////////////////////////////////////////////////////////
    // Constructor
    // /////////////////////////////////////////////////////////////////

    /**
     * Construct an elliptic curve E with the specified parameters.
     * 
     * @param a
     *                curve parameter a
     * @param b
     *                curve parameter b
     * @param q
     *                size of the underlying field
     * @see GFElement
     */
    protected EllipticCurve(GFElement a, GFElement b, FlexiBigInt q) {
	// TODO check whether the parameters match: are a and b are defined over
	// the same field, does parameter q match?
	mQ = q;
	mA = a;
	mB = b;
    }

    // /////////////////////////////////////////////////////////////////
    // Access
    // /////////////////////////////////////////////////////////////////

    /**
     * Returns the size of underlying field p.
     * 
     * @return characteristic of underlying field p
     */
    public FlexiBigInt getQ() {
	return mQ;
    }

    /**
     * @return a copy of the elliptic curve parameter a
     */
    public GFElement getA() {
	return (GFElement) mA.clone();
    }

    /**
     * @return a copy of the elliptic curve parameter b
     */
    public GFElement getB() {
	return (GFElement) mB.clone();
    }

    // /////////////////////////////////////////////////////////////////
    // Comparison
    // /////////////////////////////////////////////////////////////////

    /**
     * Compare this curve with another object.
     * 
     * @param other
     *                the other object
     * @return the result of the comparison
     */
    public boolean equals(Object other) {
	if (other == null || !(other instanceof EllipticCurve)) {
	    return false;
	}

	EllipticCurve otherCurve = (EllipticCurve) other;

	return mQ.equals(otherCurve.mQ) && mA.equals(otherCurve.mA)
		&& mB.equals(otherCurve.mB);
    }

    /**
     * @return the hash code of this curve
     */
    public int hashCode() {
	return mQ.hashCode() + mA.hashCode() + mB.hashCode();
    }

    // /////////////////////////////////////////////////////////////////
    // Output
    // /////////////////////////////////////////////////////////////////

    /**
     * @return a human readable form of this elliptic curve
     */
    public abstract String toString();

}
