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
 * This class is called, when trying to combine elements of different fields.
 * 
 * @author Birgit Henhapl
 */
public class DifferentFieldsException extends GFException {

    private static final String diagnostic = "Cannot combine elements from different fields";

    /**
     * Default constructor. Calls the parent-constructor with the message
     * "Cannot combine elements from different fields"
     */
    public DifferentFieldsException() {
	super(diagnostic);
    }

    /**
     * Calls the parent-constructor with the message "Cannot combine elements
     * from different fields: <em>details</em>"
     * 
     * @param details
     *                details of this exception
     */
    public DifferentFieldsException(String details) {
	super(diagnostic + ": " + details);
    }

}
