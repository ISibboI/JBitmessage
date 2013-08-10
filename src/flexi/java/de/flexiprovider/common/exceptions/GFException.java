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
 * This exception is the parentclass of all exceptions, that relate to the
 * gf-arithmetic.
 * 
 * @author Birgit Henhapl
 */
public class GFException extends RuntimeException {

    private static final String DIAGNOSTIC = "A field-specific exception was thrown";

    /**
     * Default constructor. Calls super-constructor with the message "A
     * field-specific exception was thrown".
     */
    public GFException() {
	super(DIAGNOSTIC);
    }

    /**
     * Calls super-constructor with the message "A field-specific exception was
     * thrown: <tt>details</tt>".
     * 
     * @param details
     *                specifies the details of this exception
     */
    public GFException(String details) {
	super(DIAGNOSTIC + ": " + details);
    }

}
