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
 * This exception is thrown, when the parameters of a method are two points from
 * different curves.
 * 
 * @author Birgit Henhapl
 * @see de.flexiprovider.common.math.ellipticcurves.Point
 * @see de.flexiprovider.common.math.ellipticcurves.PointGFP
 */
public class DifferentCurvesException extends ECException {

    private static final String diagnostic = "Cannot combine different elliptic curves";

    /**
     * Default constructor. Calls super-constructor with the message "Cannot
     * combine different elliptic curves".
     */
    public DifferentCurvesException() {
	super(diagnostic);
    }

    /**
     * Constructor with the message "Cannot combine different elliptic curves:
     * <em>detail</em>
     * 
     * @param detail
     *                details of this Exception
     */
    public DifferentCurvesException(String detail) {
	super(diagnostic + ":\n" + detail);
    }

}
