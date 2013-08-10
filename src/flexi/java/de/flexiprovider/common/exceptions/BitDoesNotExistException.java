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
 * This exception is thrown, if one bit in a Bitstring shall be modified that
 * does not exist.
 * 
 * @see de.flexiprovider.common.math.finitefields.GF2Polynomial
 */
public class BitDoesNotExistException extends GFException {

    private static final String DIAGNOSTIC = "The given Bit does not exist and thus cannot be modified";

    /**
     * Default constructor. Calls the parent-constructor with the message "The
     * given Bit does not exist and thus cannot be modified"
     */
    public BitDoesNotExistException() {
	super(DIAGNOSTIC);
    }

    /**
     * Calls the parent-constructor with the message "The given Bit does not"
     * exist and thus cannot be modified: position <em>pos</em>"
     * 
     * @param pos
     *                the position of the bit to modify
     */
    public BitDoesNotExistException(int pos) {
	super(DIAGNOSTIC + ": " + pos);
    }

}
