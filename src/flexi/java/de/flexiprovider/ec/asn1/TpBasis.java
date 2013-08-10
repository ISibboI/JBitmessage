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
import de.flexiprovider.common.util.ASN1Tools;

/**
 * This class represents a <tt>prime-field</tt> as defined in ANS X9.62 -
 * 1998. The ASN.1 definition of this structure is
 * 
 * <pre>
 *   tpBasis ::= INTEGER;
 * </pre>
 * 
 * @author Michele Boivin
 * @author Martin Döring
 */
public class TpBasis extends ASN1Integer {

    /**
     * Constructor used for decoding.
     */
    public TpBasis() {
	// do not delete this constructor !!!
	super();
    }

    /**
     * Constructor used for encoding.
     * 
     * @param tc
     *                the trinomial coefficient
     */
    public TpBasis(int tc) {
	super(tc);
    }

    /**
     * @return the trinomial coefficient
     */
    public int getTC() {
	return ASN1Tools.getFlexiBigInt(this).intValue();
    }

}
