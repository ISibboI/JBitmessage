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
 * This exception is thrown, if the given object identifier of a curve cannot be
 * found, that means, is not provided by this provider.
 * 
 * @author Birgit Henhapl
 * @see de.flexiprovider.common.math.ellipticcurves.Point
 * @see de.flexiprovider.common.math.ellipticcurves.PointGFP
 */
public class CurveNotFoundException extends ECException {

    private static final String DIAGNOSTIC = "This curve OID is not found in the provided file";

    /**
     * Default constructor. Calls super-constructor with the message "This curve
     * OID is not found in the provided file."
     */
    public CurveNotFoundException() {
	super(DIAGNOSTIC);
    }

    /**
     * Constructor with the message "This curve OID is not found in the provided
     * file: <em>oid</em>
     * 
     * @param oid
     *                the oid not recognized by the provider
     */
    public CurveNotFoundException(String oid) {
	super(DIAGNOSTIC + ": " + oid);
    }
}
