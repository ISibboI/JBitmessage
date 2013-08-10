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
 * This exception is thrown, when trying to use a polynom as field polynom,
 * which is not irreducible.
 */
public class PolynomialIsNotIrreducibleException extends GFException {

    private static final String diagnostic = "The given fieldpolynomial is not irreducible.";

    /**
     * Default constructor. Calls the parent-constructor with the message "The
     * given fieldpolynomial is not irreducible."
     */
    public PolynomialIsNotIrreducibleException() {
	super(diagnostic);
    }

}
