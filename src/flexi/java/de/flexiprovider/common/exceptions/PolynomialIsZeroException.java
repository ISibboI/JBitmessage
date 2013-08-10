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
 * This exception is thrown, when trying to divide or reduce by an element, that
 * is zero.
 * 
 * @see de.flexiprovider.common.math.finitefields.GF2Polynomial
 */
public class PolynomialIsZeroException extends GFException {

    private static final String diagnostic = "This element is Zero!";

    /**
     * Default constructor. Calls the parent-constructor with the message "This
     * element is Zero!"
     */
    public PolynomialIsZeroException() {
	super(diagnostic);
    }

}
