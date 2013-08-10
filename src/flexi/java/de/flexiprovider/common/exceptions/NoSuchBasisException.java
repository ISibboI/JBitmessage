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
 * This exception is thrown, when trying to construct an object of type
 * <tt>GF2nONBField</tt> of an extension-grade, which does not have an optimal
 * normal base.
 * 
 * @see de.flexiprovider.common.math.finitefields.GF2nONBField
 * @author Birgit Henhapl
 */
public class NoSuchBasisException extends GFException {

    private static final String diagnostic = "This extension field does not have a normal basis";

    /**
     * Default constructor. Calls the parent-constructor with the message "This
     * extension field does not have a normal basis"
     */
    public NoSuchBasisException() {
	super(diagnostic);
    }

    /**
     * Calls the parent-constructor with the message "This extension field does
     * not have a normal basis: <em>detail</em>"
     * 
     * @param detail
     *                specifies the details of this exception
     */
    public NoSuchBasisException(String detail) {
	super(diagnostic + ":\n" + detail);
    }

}
