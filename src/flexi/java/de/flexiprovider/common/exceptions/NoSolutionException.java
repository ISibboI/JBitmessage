/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.common.exceptions;

import de.flexiprovider.common.math.finitefields.GF2nElement;

/**
 * This exception is thrown, when trying to solve the equation z^2 + z = b, and
 * where z^2 + z = b has no solution.
 * 
 * @see GF2nElement
 * 
 * @author Birgit Henhapl
 */
public class NoSolutionException extends GFException {

    private static final String diagnostic = "The equation z^2 + z = b has no solution z for b";

    /**
     * Default constructor. Calls the parent-constructor with the message "The
     * equation z^2 + z = b has no solution z for b";
     */
    public NoSolutionException() {
	super(diagnostic);
    }

    /**
     * Calls the parent-constructor with the message "The equation z^2 + z = b
     * has no solution z for b = <tt>b</tt>"
     * 
     * @param b =
     *                z^2 + z
     */
    public NoSolutionException(GF2nElement b) {
	super(diagnostic + b.toString(16));
    }

}
