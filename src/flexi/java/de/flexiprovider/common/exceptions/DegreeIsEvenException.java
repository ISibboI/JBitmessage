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
 * This exception is thrown, when trying to compute the halftrace of an element
 * whose degree is even..
 */
public class DegreeIsEvenException extends GFException {

    private static final String diagnostic = "The degree of the used field is even. Cannot compute halftrace.";

    /**
     * Default constructor. Calls the parent-constructor with the message "The
     * degree of the used field is even. Cannot compute halftrace."
     */
    public DegreeIsEvenException() {
	super(diagnostic);
    }

}
