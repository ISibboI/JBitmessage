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
 * This exception is thrown, if two Bitstrings of different lengths shall be
 * vector-multiplied.
 */
public class PolynomialsHaveDifferentLengthException extends GFException {

    private static final String diagnostic = "The two Bitstrings have a different length and thus cannot be"
	    + " vector-multiplied.";

    /**
     * Default constructor. Calls the parent-constructor with the message "The
     * two Bitstrings have a different length and thus cannot be"+ "
     * vector-multiplied."
     */
    public PolynomialsHaveDifferentLengthException() {
	super(diagnostic);
    }

}
