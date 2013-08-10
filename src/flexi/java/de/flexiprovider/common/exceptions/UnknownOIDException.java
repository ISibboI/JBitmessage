/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.common.exceptions;

import de.flexiprovider.api.exceptions.InvalidParameterException;

/**
 * This exception is used for indicating unknown OIDs.
 */
public class UnknownOIDException extends InvalidParameterException {

    /**
     * Default constructor.
     */
    public UnknownOIDException() {
	super("This OID is unknown to this provider.");
    }

    /**
     * Constructor accepting an OID string.
     * 
     * @param oid
     *                the OID string
     */
    public UnknownOIDException(String oid) {
	super("OID " + oid + " is unknown to this provider.");
    }

    /**
     * Constructor accepting an OID given as int array.
     * 
     * @param oid
     *                the OID int array
     */
    public UnknownOIDException(int[] oid) {
	super("OID " + oidToString(oid) + " is unknown to this provider.");
    }

    private static String oidToString(int[] oid) {
	String result = "";
	for (int i = 0; i < oid.length - 1; i++) {
	    result += +oid[i] + ".";
	}
	result += oid[oid.length - 1];
	return result;
    }

}
