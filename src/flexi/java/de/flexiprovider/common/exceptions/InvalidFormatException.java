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
 * This exception is thrown, if a point is stored in a byte array in a wrong
 * format. For a compressed point the first field has to hold a 2 or 3, for an
 * uncompressed form a 4 and for an hybrid form a 6 or 7.
 * 
 * @author Birgit Henhapl
 * @see de.flexiprovider.common.math.ellipticcurves.Point
 * @see de.flexiprovider.common.math.ellipticcurves.PointGFP
 */
public class InvalidFormatException extends ECException {

    private static final String diagnostic = "The byte array, storing the point, has the wrong format";

    /**
     * Constructs an InvalidFormatException with no detail message. A detail
     * message is a String that describes this particular exception.
     */
    public InvalidFormatException() {
	super(diagnostic);
    }

    /**
     * Constructs an InvalidFormatException with a detail message. A detail
     * message is a String that describes this particular exception.
     * 
     * @param msg
     *                the detail message
     */
    public InvalidFormatException(String msg) {
	super(diagnostic + ": " + msg);
    }

    /**
     * Constructs an InvalidFormatException with detailed message. It tells
     * about the content of the first byte and repeats the rules to use the byte
     * array representation.
     * 
     * @param type
     *                the value of the first byte in the byte array
     */
    public InvalidFormatException(byte type) {
	super("diagnostic:\n" + type + " is an invalid type of point"
		+ "representation:\n\t2, 3: compressed form,\n\t4"
		+ ": uncompressed form\n\t6, 7: hybrid form");
    }

}
