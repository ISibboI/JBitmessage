/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.ec.asn1;

import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1OpenType;
import codec.asn1.ASN1Sequence;

/**
 * This class represents a <tt>FieldId</tt> as defined in ANS X9.62 - 1998.
 * The ASN.1 definition of this structure is
 * 
 * <pre>
 *   FieldID ::= SEQUENCE{
 *   fieldType   OBJECT IDENTIFIER,
 *   parameters  OpenType
 * }
 * </pre>
 * 
 * <tt>Parameters</tt> Parameters are the Parameters defined in the internet
 * draft ... for elliptic curves
 * 
 * @author Michele Boivin
 * @author Martin Döring
 */
public class FieldId extends ASN1Sequence {

    /*-------------------------------------------------
     * FIELD AND BASIS TYPES
     -------------------------------------------------*/

    /**
     * OID identifying prime fields
     */
    static final ASN1ObjectIdentifier PRIME_FIELD = new ASN1ObjectIdentifier(
	    "1.2.840.10045.1.1");
    /**
     * OID identifying characteristic two fields
     */
    static final ASN1ObjectIdentifier CHARACTERISTIC_TWO_FIELD = new ASN1ObjectIdentifier(
	    "1.2.840.10045.1.2");
    /**
     * OID identifying Gaussian (orthonormal) basis type
     */
    public static final ASN1ObjectIdentifier BASIS_TYPE_ONB = new ASN1ObjectIdentifier(
	    "1.2.840.10045.1.2.3.1");
    /**
     * OID identifying trinomial basis type
     */
    public static final ASN1ObjectIdentifier BASIS_TYPE_TRINOMIAL = new ASN1ObjectIdentifier(
	    "1.2.840.10045.1.2.3.2");
    /**
     * OID identifying pentanomial basis type
     */
    public static final ASN1ObjectIdentifier BASIS_TYPE_PENTANOMIAL = new ASN1ObjectIdentifier(
	    "1.2.840.10045.1.2.3.3");

    /**
     * The OID identifying the field type. This parameter is only used for
     * decoding this structure.
     */
    private ASN1ObjectIdentifier fieldType;

    /**
     * Constructor used for decoding.
     */
    public FieldId() {
	super(2);
	fieldType = new ASN1ObjectIdentifier();
	add(fieldType);
	add(new ASN1OpenType(new ECurvesOIDRegistry(), fieldType));
    }

    /**
     * Constructor for prime fields.
     * 
     * @param pF
     *                an instance of PrimeField
     */
    public FieldId(PrimeField pF) {
	super(2);
	add(PRIME_FIELD);
	add(pF);
    }

    /**
     * Constructor for characteristic-two fields.
     * 
     * @param cTF
     *                an instance of GF2nField
     */
    public FieldId(CharacteristicTwoField cTF) {
	super(2);
	add(CHARACTERISTIC_TWO_FIELD);
	add(cTF);
    }

    /**
     * Return the second parameter as {@link ASN1OpenType}. The inner type is
     * either an instance of {@link PrimeField} or an instance of
     * {@link CharacteristicTwoField})
     * 
     * @return the second parameter as {@link ASN1OpenType}
     */
    public ASN1OpenType getField() {
	return (ASN1OpenType) get(1);
    }

}
