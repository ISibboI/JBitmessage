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
 * This interface defines a finite field element. It is implemented by the
 * classes {@link GFPElement} and {@link GF2nElement}.
 * 
 * @see GFPElement
 * @see GF2nElement
 * 
 * @author Birgit Henhapl
 * @author Martin Döring
 */
public interface GFElement {

    /**
     * @return a copy of this GFElement
     */
    Object clone();

    // /////////////////////////////////////////////////////////////////
    // comparison
    // /////////////////////////////////////////////////////////////////

    /**
     * Compare this curve with another object.
     * 
     * @param other
     *                the other object
     * @return the result of the comparison
     */
    boolean equals(Object other);

    /**
     * @return the hash code of this element
     */
    int hashCode();

    /**
     * Checks whether this element is zero.
     * 
     * @return <tt>true</tt> if <tt>this</tt> is the zero element
     */
    boolean isZero();

    /**
     * Checks whether this element is one.
     * 
     * @return <tt>true</tt> if <tt>this</tt> is the one element
     */
    boolean isOne();

    // /////////////////////////////////////////////////////////////////////
    // arithmetic
    // /////////////////////////////////////////////////////////////////////

    /**
     * Compute the sum of this element and the addend.
     * 
     * @param addend
     *                the addend
     * @return <tt>this + other</tt> (newly created)
     * @throws DifferentFieldsException
     *                 if the elements are of different fields.
     */
    GFElement add(GFElement addend) throws DifferentFieldsException;

    /**
     * Compute the sum of this element and the addend, overwriting this element.
     * 
     * @param addend
     *                the addend
     * @throws DifferentFieldsException
     *                 if the elements are of different fields.
     */
    void addToThis(GFElement addend) throws DifferentFieldsException;

    /**
     * Compute the difference of this element and <tt>minuend</tt>.
     * 
     * @param minuend
     *                the minuend
     * @return <tt>this - minuend</tt> (newly created)
     * @throws DifferentFieldsException
     *                 if the elements are of different fields.
     */
    GFElement subtract(GFElement minuend) throws DifferentFieldsException;

    /**
     * Compute the difference of this element and <tt>minuend</tt>,
     * overwriting this element.
     * 
     * @param minuend
     *                the minuend
     * @throws DifferentFieldsException
     *                 if the elements are of different fields.
     */
    void subtractFromThis(GFElement minuend);

    /**
     * Compute the product of this element and <tt>factor</tt>.
     * 
     * @param factor
     *                the factor
     * @return <tt>this * factor</tt> (newly created)
     * @throws DifferentFieldsException
     *                 if the elements are of different fields.
     */
    GFElement multiply(GFElement factor) throws DifferentFieldsException;

    /**
     * Compute <tt>this * factor</tt> (overwrite <tt>this</tt>).
     * 
     * @param factor
     *                the factor
     * @throws DifferentFieldsException
     *                 if the elements are of different fields.
     */
    void multiplyThisBy(GFElement factor) throws DifferentFieldsException;

    /**
     * Compute the multiplicative inverse of this element.
     * 
     * @return <tt>this<sup>-1</sup></tt> (newly created)
     * @throws ArithmeticException
     *                 if <tt>this</tt> is the zero element.
     */
    GFElement invert() throws ArithmeticException;

    // /////////////////////////////////////////////////////////////////////
    // conversion
    // /////////////////////////////////////////////////////////////////////

    /**
     * Returns this element as FlexiBigInt. The conversion is <a
     * href="http://grouper.ieee.org/groups/1363/">P1363</a>-conform.
     * 
     * @return this element as FlexiBigInt
     */
    FlexiBigInt toFlexiBigInt();

    /**
     * Returns this element as byte array. The conversion is <a href =
     * "http://grouper.ieee.org/groups/1363/">P1363</a>-conform.
     * 
     * @return this element as byte array
     */
    byte[] toByteArray();

    /**
     * Return a String representation of this element.
     * 
     * @return String representation of this element
     */
    String toString();

    /**
     * Return a String representation of this element. <tt>radix</tt>
     * specifies the radix of the String representation.
     * 
     * @param radix
     *                specifies the radix of the String representation
     * 
     * @return String representation of this element with the specified radix
     */
    String toString(int radix);

}
