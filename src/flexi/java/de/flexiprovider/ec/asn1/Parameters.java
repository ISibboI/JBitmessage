/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.ec.asn1;

import codec.asn1.ASN1Choice;
import codec.asn1.ASN1Null;
import codec.asn1.ASN1ObjectIdentifier;

/**
 * This class represents a <tt>Parameter</tt> ASN.1 structure as defined in
 * ANSI X9.62 - 1998. The ASN.1 definition of this structure is
 * <p>
 * 
 * <pre>
 *  Parameters ::= CHOICE {
 *    ecParameters   ECParameters
 *    namedCurve     CURVES.&amp;id({CurveNames})
 *    implicitlyCA   NULL
 *  }
 * </pre>
 * 
 * @author Michele Boivin
 */
public class Parameters extends ASN1Choice {

    /**
     * The default constructor adds the supported types to this choice.
     */
    public Parameters() {
	// create an instance of ASN1Choice with capacity 3.
	super(3);
	addType(new ASN1ObjectIdentifier());
	addType(new ECDomainParameters());
	addType(new ASN1Null());
    }

}
