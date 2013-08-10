/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.common.exceptions;

/**
 * This exception is thrown, if the given object identifier of a curve cannot be
 * found.
 * 
 * @author Birgit Henhapl
 * @see de.flexiprovider.common.math.ellipticcurves.EllipticCurveGFP
 * @see de.flexiprovider.common.math.ellipticcurves.PointGFP
 */
public class InvalidCurveTypeException extends ECException {

    /**
     * Constructs an InvalidCurveTypeException with no detail message. A detail
     * message is a String that describes this particular exception.
     */
    public InvalidCurveTypeException() {
	super();
    }

    /**
     * Constructs an InvalidCurveTypeException with detail message. The message
     * tells the user, that that particular object identifier could not be
     * found.
     * 
     * @param msg
     *                the filename in which the oid is looked for
     */
    public InvalidCurveTypeException(String msg) {
	super("The object identifier of the given curve"
		+ "doesn't belong to the group of " + msg + " curves");
    }

}
