/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.common.exceptions;

import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.math.ellipticcurves.EllipticCurve;
import de.flexiprovider.common.math.finitefields.GF2nElement;

/**
 * This exception is thrown, if a point shall be constructed, that is not on the
 * underlying curve.
 * 
 * @author Birgit Henhapl
 * @see de.flexiprovider.common.math.ellipticcurves.Point
 * @see EllipticCurve
 */
public class InvalidPointException extends ECException {

    /**
     * Constructs an InvalidPointException with no detail message. A detail
     * message is a String that describes this particular exception.
     */
    public InvalidPointException() {
	super("InvalidPointException");
    }

    /**
     * Constructs an InvalidPointException with the specified detail message. A
     * detail message is a String that describes this particular exception.
     * 
     * @param msg
     *                detail message
     */
    public InvalidPointException(String msg) {
	super(msg);
    }

    /**
     * Constructs an InvalidPointException with the specified detail message.
     * The detail message tells the user, that the point, belonging to the
     * parameters <tt>x</tt> and <tt>y</tt> is not on curve <tt>E</tt>.
     * 
     * @param x
     *                the x-coordinate of the point to be constructed
     * @param y
     *                the y-coordinate of the point to be constructed
     * @param e
     *                the underlying curve
     */
    public InvalidPointException(FlexiBigInt x, FlexiBigInt y, EllipticCurve e) {
	super("InvalidPointException:\n" + "point (" + x + ", " + y
		+ ") \nis not on curve\n" + "E: " + e.toString());
    }

    /**
     * Constructs an InvalidPointException with the specified detail message.
     * The detail message tells the user, that the point, belonging to the
     * parameters <tt>x</tt> and <tt>y</tt> is not on curve <tt>E</tt>.
     * 
     * @param x
     *                the x-coordinate of the point to be constructed
     * @param y
     *                the y-coordinate of the point to be constructed
     * @param e
     *                the underlying curve
     */
    public InvalidPointException(GF2nElement x, GF2nElement y, EllipticCurve e) {
	super("InvalidPointException:\n" + "point (" + x + ", " + y
		+ ") \nis not on curve\n" + "E: " + e.toString());
    }

    /**
     * Constructs an InvalidPointException with the specified detail message.
     * The detail message tells the user, that the point, belonging to the
     * parameters <tt>x</tt>, <tt>y</tt> and <tt>z</tt> is not on curve
     * <tt>E</tt>.
     * 
     * @param x
     *                the x-coordinate of the point to be constructed
     * @param y
     *                the y-coordinate of the point to be constructed
     * @param z
     *                the z-coordinate of the point to be constructed
     * @param e
     *                the underlying curve
     */
    public InvalidPointException(FlexiBigInt x, FlexiBigInt y, FlexiBigInt z,
	    EllipticCurve e) {
	super("InvalidPointException:\n" + "point (" + x + ", " + y + ", " + z
		+ ") \nis" + " not on curve \nE: " + e.toString());
    }

}
