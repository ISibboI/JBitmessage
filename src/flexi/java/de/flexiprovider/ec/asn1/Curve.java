/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.ec.asn1;

import codec.asn1.ASN1OctetString;
import codec.asn1.ASN1Sequence;
import de.flexiprovider.common.math.finitefields.GFElement;

/**
 * This class represents a <tt>Curve</tt> as defined in ANS X9.62 - 1998. The
 * ASN.1 definition of this structure is
 * 
 * <pre>
 *  Curve ::= SEQUENCE {
 *   a     fieldElement,
 *   b     fieldElement,
 *   seed  BIT STRING OPTIONAL,
 * }
 * 
 *  FieldElement ::= OCTET STRING;
 * </pre>
 * 
 * <tt>Parameters</tt> Parameters are the Parameters defined in the internet
 * draft ... for elliptic curves
 * 
 * @author Michele Boivin
 */
public class Curve extends ASN1Sequence {

    /**
     * Default constructor. The optional seed is omitted.
     */
    public Curve() {
	super(3);
	add(new ASN1OctetString());
	add(new ASN1OctetString());
    }

    /**
     * Constructor from two curve coefficients. The optional seed is omitted.
     * 
     * @param a
     *                the curve coefficient a
     * @param b
     *                the curve coefficient b
     */
    public Curve(ASN1OctetString a, ASN1OctetString b) {
	super(2);
	add(a);
	add(b);
    }

    /**
     * Constructor from two curve coefficients. The optional seed is omitted.
     * 
     * @param a
     *                the curve coefficient a
     * @param b
     *                the curve coefficient b
     */
    public Curve(GFElement a, GFElement b) {
	super(2);
	add(new ASN1OctetString(filterByteArray(a.toByteArray())));
	add(new ASN1OctetString(filterByteArray(b.toByteArray())));
    }

    /**
     * @return the curve coefficient a
     */
    byte[] getA() {
	return ((ASN1OctetString) get(0)).getByteArray();
    }

    /**
     * @return the curve coefficient b
     */
    byte[] getB() {
	return ((ASN1OctetString) get(1)).getByteArray();
    }

    private static byte[] filterByteArray(byte[] array) {
	if ((array[0] == 0) && (array.length > 1)) {
	    if (array[1] < 0) {
		int n = array.length - 1;
		byte[] erg = new byte[n];
		System.arraycopy(array, 1, erg, 0, erg.length);
		return erg;
	    }
	    return array;
	}
	return array;
    }

}
