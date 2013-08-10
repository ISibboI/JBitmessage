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
import codec.asn1.ASN1Null;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1OpenType;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1Type;
import codec.asn1.ResolverException;
import de.flexiprovider.common.util.ASN1Tools;

/**
 * This class represents a <tt>characterisitic-two-field</tt> as defined in
 * ANS X9.62 - 1998. The ASN.1 definition of this structure is
 * 
 * <pre>
 *   characteristic-two-field::= SEQUENCE{
 *                  m             Integer,
 *                  basis         ObjectIdentifier,
 *                  parameters    OpenType
 *                  }
 * </pre>
 * 
 * @author Michele Boivin
 * @author Martin Döring
 */
public class CharacteristicTwoField extends ASN1Sequence {

    /**
     * The OID identifying the basis type. This parameter is only used for
     * decoding this structure.
     */
    private ASN1ObjectIdentifier basisType;

    /**
     * Constructor used for decoding.
     */
    public CharacteristicTwoField() {
	super(3);
	basisType = new ASN1ObjectIdentifier();
	add(new ASN1Integer());
	add(basisType);
	add(new ASN1OpenType(new ECurvesOIDRegistry(), basisType));
    }

    /**
     * Constructor for a Gaussian basis representation.
     * 
     * @param n
     *                the extension degree of the finite field GF(2^n)
     */
    public CharacteristicTwoField(int n) {
	super(3);
	add(new ASN1Integer(n));
	add(FieldId.BASIS_TYPE_ONB);
	add(new ASN1Null());
    }

    /**
     * Constructor for trinomial basis representation. The field polynomial is
     * of the form <tt>x^n + x^tc + 1</tt>.
     * 
     * @param n
     *                the extension degree of the finite field GF(2^n)
     * @param tc
     *                the value for trinomial basis representation
     */
    public CharacteristicTwoField(int n, int tc) {
	super(3);
	add(new ASN1Integer(n));
	add(FieldId.BASIS_TYPE_TRINOMIAL);
	add(new TpBasis(tc));
    }

    /**
     * Constructor for pentanomial basis representation. The field polynomial is
     * of the form <tt>x^n + x^pc3 + x^pc2 + x^pc1 + 1</tt>.
     * 
     * @param n
     *                the extension degree of the finite field GF(2^n)
     * @param pc1
     *                the first value for pentanomial basis representation
     * @param pc2
     *                the second value for pentanomial basis representation
     * @param pc3
     *                the thrid value for pentanomial basis representation
     */
    public CharacteristicTwoField(int n, int pc1, int pc2, int pc3) {
	super(3);
	add(new ASN1Integer(n));
	add(FieldId.BASIS_TYPE_PENTANOMIAL);
	add(new PpBasis(pc1, pc2, pc3));
    }

    /**
     * @return whether this field uses Gaussian basis representation
     */
    public boolean isONB() {
	return ((ASN1ObjectIdentifier) get(1)).equals(FieldId.BASIS_TYPE_ONB);
    }

    /**
     * @return whether this field uses trinomial basis representation
     */
    public boolean isTrinomial() {
	return ((ASN1ObjectIdentifier) get(1))
		.equals(FieldId.BASIS_TYPE_TRINOMIAL);
    }

    /**
     * @return whether this field uses pentanomial basis representation
     */
    public boolean isPentanomial() {
	return ((ASN1ObjectIdentifier) get(1))
		.equals(FieldId.BASIS_TYPE_PENTANOMIAL);
    }

    /**
     * @return the extension degree of the finite field GF(2^n)
     */
    public int getN() {
	return ASN1Tools.getFlexiBigInt((ASN1Integer) get(0)).intValue();
    }

    /**
     * @return the trinomial basis
     */
    public TpBasis getTrinom() {
	ASN1Type type = (ASN1Type) get(2);
	if (type instanceof TpBasis) {
	    // if type already is an instance of TpBasis, return it
	    return (TpBasis) type;
	}

	// else, type is an instance of ASN1OpenType, so get the inner type
	try {
	    return (TpBasis) ((ASN1OpenType) type).getInnerType();
	} catch (ResolverException re) {
	    throw new RuntimeException("ResolverException: " + re.getMessage());
	}
    }

    /**
     * @return the pentanomial basis
     */
    public PpBasis getPenta() {
	ASN1Type type = (ASN1Type) get(2);
	if (type instanceof PpBasis) {
	    // if type already is an instance of PpBasis, return it
	    return (PpBasis) type;
	}

	// else, type is an instance of ASN1OpenType, so get the inner type
	try {
	    return (PpBasis) ((ASN1OpenType) type).getInnerType();
	} catch (ResolverException re) {
	    throw new RuntimeException("ResolverException: " + re.getMessage());
	}
    }

}
