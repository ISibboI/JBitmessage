/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.ec.asn1;

import codec.asn1.ASN1Integer;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.util.ASN1Tools;

/**
 * This class represents a <tt>prime-field</tt> as defined in ANS X9.62 -
 * 1998. The ASN.1 definition of this structure is
 * 
 * <pre>
 *   prime-field ::= INTEGER;
 * </pre>
 * 
 * @author Michele Boivin
 * @author Martin Döring
 */
public class PrimeField extends ASN1Integer {

    /**
     * Constructor used for decoding.
     */
    public PrimeField() {
	// do not delete this constructor !!!
	super();
    }

    /**
     * Constructor used for encoding.
     * 
     * @param order
     *                the field order
     */
    public PrimeField(FlexiBigInt order) {
	super(order.toByteArray());
    }

    /**
     * @return the field order
     */
    public FlexiBigInt getQ() {
	return ASN1Tools.getFlexiBigInt(this);
    }

}
