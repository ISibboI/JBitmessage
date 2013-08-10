/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */
package de.flexiprovider.common.math.finitefields;

import de.flexiprovider.common.exceptions.DifferentFieldsException;
import de.flexiprovider.common.math.FlexiBigInt;

/**
 * This class implements an element of the finite field GF(p), where p is a
 * large prime.
 * 
 * @see GF2nElement
 * @see GFPElement
 * @author Birgit Henhapl
 * @author Martin Döring
 */
public class GFPElement implements GFElement {

    private FlexiBigInt mValue;

    private FlexiBigInt mP;

    // /////////////////////////////////////////////////////////////////////
    // constructors
    // /////////////////////////////////////////////////////////////////////

    /**
     * Create a new GFPElement from the given value and field order.
     * 
     * @param value
     *                the value
     * @param p
     *                the order of the field
     */
    public GFPElement(FlexiBigInt value, FlexiBigInt p) {
	mValue = value.mod(p);
	mP = p;
    }

    /**
     * Create a new GFPElement from the given encoded value and field order.
     * 
     * @param encValue
     *                the encoded value
     * @param p
     *                the order of the field
     */
    public GFPElement(byte[] encValue, FlexiBigInt p) {
	mValue = new FlexiBigInt(1, encValue).mod(p);
	mP = p;
    }

    /**
     * Copy constructor.
     * 
     * @param other
     *                another GFPElement
     */
    public GFPElement(GFPElement other) {
	mValue = other.mValue;
	mP = other.mP;
    }

    // /////////////////////////////////////////////////////////////////////
    // pseudo-constructors
    // /////////////////////////////////////////////////////////////////////

    /**
     * @return a copy of this GFPElement
     */
    public Object clone() {
	return new GFPElement(this);
    }

    /**
     * Create the zero element.
     * 
     * @param p
     *                the modulus
     * @return the zero element in GF(p)
     */
    public static GFPElement ZERO(FlexiBigInt p) {
	return new GFPElement(FlexiBigInt.ZERO, p);
    }

    /**
     * Create the one element.
     * 
     * @param p
     *                the modulus
     * @return the one element in GF(p)
     */
    public static GFPElement ONE(FlexiBigInt p) {
	return new GFPElement(FlexiBigInt.ONE, p);
    }

    // /////////////////////////////////////////////////////////////////////
    // comparison
    // /////////////////////////////////////////////////////////////////////

    /**
     * Checks whether this element is zero.
     * 
     * @return <tt>true</tt> if <tt>this</tt> is the zero element
     */
    public boolean isZero() {
	return mValue.equals(FlexiBigInt.ZERO);
    }

    /**
     * Checks whether this element is one.
     * 
     * @return <tt>true</tt> if <tt>this</tt> is the one element
     */
    public boolean isOne() {
	return mValue.equals(FlexiBigInt.ONE);
    }

    /**
     * Compare this element with another object.
     * 
     * @param other
     *                the other object
     * @return <tt>true</tt> if the two objects are equal, <tt>false</tt>
     *         otherwise
     */
    public boolean equals(Object other) {
	if (other == null || !(other instanceof GFPElement)) {
	    return false;
	}

	GFPElement otherElement = (GFPElement) other;

	if (mP.equals(otherElement.mP) && mValue.equals(otherElement.mValue)) {
	    return true;
	}

	return false;
    }

    /**
     * @return the hash code of this element
     */
    public int hashCode() {
	return mP.hashCode() + mValue.hashCode();
    }

    // /////////////////////////////////////////////////////////////////////
    // arithmetic
    // /////////////////////////////////////////////////////////////////////

    /**
     * Compute the sum of this element and <tt>addend</tt>.
     * 
     * @param addend
     *                the addend
     * @return <tt>this + other</tt> (newly created)
     * @throws DifferentFieldsException
     *                 if the elements are of different fields.
     */
    public GFElement add(GFElement addend) throws DifferentFieldsException {
	GFPElement result = new GFPElement(this);
	result.addToThis(addend);
	return result;
    }

    /**
     * Compute <tt>this + addend</tt> (overwrite <tt>this</tt>).
     * 
     * @param addend
     *                the addend
     * @throws DifferentFieldsException
     *                 if the elements are of different fields.
     */
    public void addToThis(GFElement addend) throws DifferentFieldsException {
	if (!(addend instanceof GFPElement)) {
	    throw new DifferentFieldsException();
	}
	if (!(mP.equals(((GFPElement) addend).mP))) {
	    throw new DifferentFieldsException(
		    "Elements are of different fields.");
	}

	mValue = mValue.add(((GFPElement) addend).mValue).mod(mP);
    }

    /**
     * Compute the difference of this element and <tt>minuend</tt>.
     * 
     * @param minuend
     *                the minuend
     * @return <tt>this - minuend</tt> (newly created)
     * @throws DifferentFieldsException
     *                 if the elements are of different fields.
     */
    public GFElement subtract(GFElement minuend)
	    throws DifferentFieldsException {
	GFPElement result = new GFPElement(this);
	result.subtractFromThis(minuend);
	return result;
    }

    /**
     * Compute the difference of this element and <tt>minuend</tt>,
     * overwriting this element.
     * 
     * @param minuend
     *                the minuend
     * @throws DifferentFieldsException
     *                 if the elements are of different fields.
     */
    public void subtractFromThis(GFElement minuend)
	    throws DifferentFieldsException {
	if (!(minuend instanceof GFPElement)) {
	    throw new DifferentFieldsException();
	}
	mValue = mValue.subtract(((GFPElement) minuend).mValue).mod(mP);
    }

    /**
     * Compute the additive inverse of this element.
     * 
     * @return <tt>-this</tt> (newly created)
     */
    public GFPElement negate() {
	return new GFPElement(mValue.negate(), mP);
    }

    /**
     * Compute the product of this element and <tt>factor</tt>.
     * 
     * @param factor
     *                the factor
     * @return <tt>this * factor</tt> (newly created)
     * @throws DifferentFieldsException
     *                 if the elements are of different fields.
     */
    public GFElement multiply(GFElement factor) throws DifferentFieldsException {
	GFPElement result = new GFPElement(this);
	result.multiplyThisBy(factor);
	return result;
    }

    /**
     * Compute <tt>this * factor</tt> (overwrite <tt>this</tt>).
     * 
     * @param factor
     *                the factor
     * @throws DifferentFieldsException
     *                 if the elements are of different fields.
     */
    public void multiplyThisBy(GFElement factor)
	    throws DifferentFieldsException {
	if (!(factor instanceof GFPElement)) {
	    throw new DifferentFieldsException();
	}
	if (!(mP.equals(((GFPElement) factor).mP))) {
	    throw new DifferentFieldsException(
		    "Elements are of different fields.");
	}

	mValue = mValue.multiply(((GFPElement) factor).mValue).mod(mP);
    }

    /**
     * Compute the multiplicative inverse of this element.
     * 
     * @return <tt>this<sup>-1</sup></tt> (newly created)
     * @throws ArithmeticException
     *                 if <tt>this</tt> is the zero element.
     */
    public GFElement invert() throws ArithmeticException {
	if (isZero()) {
	    throw new ArithmeticException();
	}

	return new GFPElement(mValue.modInverse(mP), mP);
    }

    // /////////////////////////////////////////////////////////////////////
    // conversion
    // /////////////////////////////////////////////////////////////////////

    /**
     * @return this element as byte array
     */
    public byte[] toByteArray() {
	return mValue.toByteArray();
    }

    /**
     * @return this element as FlexiBigInt
     */
    public FlexiBigInt toFlexiBigInt() {
	return mValue;
    }

    /**
     * @return a human readable form of this element
     */
    public String toString() {
	return mValue.toString(16);
    }

    public String toString(int radix) {
	return mValue.toString(radix);
    }

}
