/* ========================================================================
 *
 *  This file is part of CODEC, which is a Java package for encoding
 *  and decoding ASN.1 data structures.
 *
 *  Author: Fraunhofer Institute for Computer Graphics Research IGD
 *          Department A8: Security Technology
 *          Fraunhoferstr. 5, 64283 Darmstadt, Germany
 *
 *  Rights: Copyright (c) 2004 by Fraunhofer-Gesellschaft 
 *          zur Foerderung der angewandten Forschung e.V.
 *          Hansastr. 27c, 80686 Munich, Germany.
 *
 * ------------------------------------------------------------------------
 *
 *  The software package is free software; you can redistribute it and/or 
 *  modify it under the terms of the GNU Lesser General Public License as 
 *  published by the Free Software Foundation; either version 2.1 of the 
 *  License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful, but 
 *  WITHOUT ANY WARRANTY; without even the implied warranty of 
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public 
 *  License along with this software package; if not, write to the Free 
 *  Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, 
 *  MA 02110-1301, USA or obtain a copy of the license at 
 *  http://www.fsf.org/licensing/licenses/lgpl.txt.
 *
 * ------------------------------------------------------------------------
 *
 *  The CODEC library can solely be used and distributed according to 
 *  the terms and conditions of the GNU Lesser General Public License for 
 *  non-commercial research purposes and shall not be embedded in any 
 *  products or services of any user or of any third party and shall not 
 *  be linked with any products or services of any user or of any third 
 *  party that will be commercially exploited.
 *
 *  The CODEC library has not been tested for the use or application 
 *  for a determined purpose. It is a developing version that can 
 *  possibly contain errors. Therefore, Fraunhofer-Gesellschaft zur 
 *  Foerderung der angewandten Forschung e.V. does not warrant that the 
 *  operation of the CODEC library will be uninterrupted or error-free. 
 *  Neither does Fraunhofer-Gesellschaft zur Foerderung der angewandten 
 *  Forschung e.V. warrant that the CODEC library will operate and 
 *  interact in an uninterrupted or error-free way together with the 
 *  computer program libraries of third parties which the CODEC library 
 *  accesses and which are distributed together with the CODEC library.
 *
 *  Fraunhofer-Gesellschaft zur Foerderung der angewandten Forschung e.V. 
 *  does not warrant that the operation of the third parties's computer 
 *  program libraries themselves which the CODEC library accesses will 
 *  be uninterrupted or error-free.
 *
 *  Fraunhofer-Gesellschaft zur Foerderung der angewandten Forschung e.V. 
 *  shall not be liable for any errors or direct, indirect, special, 
 *  incidental or consequential damages, including lost profits resulting 
 *  from the combination of the CODEC library with software of any user 
 *  or of any third party or resulting from the implementation of the 
 *  CODEC library in any products, systems or services of any user or 
 *  of any third party.
 *
 *  Fraunhofer-Gesellschaft zur Foerderung der angewandten Forschung e.V. 
 *  does not provide any warranty nor any liability that utilization of 
 *  the CODEC library will not interfere with third party intellectual 
 *  property rights or with any other protected third party rights or will 
 *  cause damage to third parties. Fraunhofer Gesellschaft zur Foerderung 
 *  der angewandten Forschung e.V. is currently not aware of any such 
 *  rights.
 *
 *  The CODEC library is supplied without any accompanying services.
 *
 * ========================================================================
 */
package codec.asn1;

import java.util.Calendar;
import java.util.Date;

/**
 * This is the Generalized Time class. In principle, the known time types are
 * all of type <code>VisibleString</code>. GeneralizedTime is defined as
 * <code>
 * [{@link ASN1#TAG_GENERALIZEDTIME UNIVERSAL 24}] IMPLICIT VisibleString
 * </code>.
 * This class automatically represents dates internally in a DER compliant
 * format, and parses dates according to BER. The internal representation is not
 * changed from BER to DER on decoding. This is to ensure that decoding and
 * encoding restore bitwise identical encodings.
 * 
 * @author Volker Roth
 * @version "$Id: ASN1GeneralizedTime.java,v 1.13 2004/09/20 15:16:30 pebinger
 *          Exp $"
 */
public class ASN1GeneralizedTime extends ASN1Time {
    /**
     * The <code>Calendar</code> fields used upon encoding date values.
     */
    private static final int[] FIELDS = { Calendar.YEAR, Calendar.MONTH,
	    Calendar.DATE, Calendar.HOUR_OF_DAY, Calendar.MINUTE,
	    Calendar.SECOND, Calendar.MILLISECOND };

    /**
     * The lengths of the encoded fields in characters.
     */
    private static final int[] LENGTHS = { 4, 2, 2, 2, 2, -2, 0 };

    /**
     * Corrections to be applied to the fields of a <code>
     * Calendar</code>.
     * Corrections are substracted from <code>Calendar</code> fields on
     * encoding, and are added on decoding.
     */
    private static final int[] CORRECT = { 0, -1, 0, 0, 0, 0, 0 };

    /**
     * Creates an instance. The value of this instance is set to the current
     * date.
     */
    public ASN1GeneralizedTime() {
	setDate(new Date(0));
    }

    /**
     * Creates an instance with the given date string. The date string must be
     * well-formed according to the BER.
     * 
     * @param time
     *                The string representation of the date.
     * @throws IllegalArgumentException
     *                 if the given string has a bad format.
     * @throws StringIndexOutOfBoundsException
     *                 if the string is not well-formed.
     */
    public ASN1GeneralizedTime(String time) {
	setDate(time);
    }

    /**
     * Creates an instance with the given date.
     * 
     * @param cal
     *                The <code>Calendar</code>.
     */
    public ASN1GeneralizedTime(Calendar cal) {
	setDate(cal);
    }

    /**
     * Creates an instance with the given date.
     * 
     * @param date
     *                The date.
     */
    public ASN1GeneralizedTime(Date date) {
	setDate(date);
    }

    /**
     * Creates an instance with the given number of milliseconds since January
     * 1, 1970, 00:00:00 GMT.
     * 
     * @param time
     *                The time.
     */
    public ASN1GeneralizedTime(long time) {
	setDate(time);
    }

    protected int[] getFields() {
	return (int[]) FIELDS.clone();
    }

    protected int[] getFieldLengths() {
	return (int[]) LENGTHS.clone();
    }

    protected int[] getFieldCorrections() {
	return (int[]) CORRECT.clone();
    }

    public int getTag() {
	return ASN1.TAG_GENERALIZEDTIME;
    }

}
