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
 * This is the root class of all ASN.1 time types. In principle, the known time
 * types are all of type VisibleString. UTCTime is defined as
 * <tt>[{@link ASN1#TAG_UTCTIME UNIVESAL 23}] IMPLICIT
 * VisibleString</tt>.
 * 
 * @author Volker Roth
 * @version "$Id: ASN1UTCTime.java,v 1.6 2004/09/20 15:18:12 pebinger Exp $"
 */
public class ASN1UTCTime extends ASN1Time {
    /**
     * The <code>Calendar</code> fields used upon encoding date values.
     */
    private static final int[] FIELDS = { Calendar.YEAR, Calendar.MONTH,
	    Calendar.DATE, Calendar.HOUR_OF_DAY, Calendar.MINUTE,
	    Calendar.SECOND };

    /**
     * The lengths of the encoded fields in characters.
     */
    private static final int[] LENGTHS = { 2, 2, 2, 2, 2, -2 };

    /**
     * Corrections to be applied to the fields of a <code>
     * Calendar</code>.
     * Corrections are substracted from <code>Calendar</code> fields on
     * encoding, and are added on decoding.
     */
    private static final int[] CORRECT = { 0, -1, 0, 0, 0, 0 };

    /**
     * Creates an instance. The value of this instance is set to the current
     * date.
     */
    public ASN1UTCTime() {
	setDate(new Date(0));
    }

    /**
     * Creates an instance with the given date string. The date string must be
     * well-formed according to the DER encoding of UTCTime.
     * 
     * @param date
     *                The string representation of the date.
     * @throws IllegalArgumentException
     *                 if the given string is not a valid date accoridng to
     *                 X.680.
     * @throws StringIndexOutOfBoundsException
     *                 if the string is not well-formed.
     */
    public ASN1UTCTime(String date) {
	setDate(date);
    }

    /**
     * Creates an instance with the given Calendar.
     * 
     * @param cal
     *                The Calendar.
     */
    public ASN1UTCTime(Calendar cal) {
	setDate(cal);
    }

    /**
     * Creates an instance with the given date.
     * 
     * @param date
     *                The date.
     */
    public ASN1UTCTime(Date date) {
	setDate(date);
    }

    /**
     * Method declaration.
     * 
     * 
     * @return The tag value
     */
    public int getTag() {
	return ASN1.TAG_UTCTIME;
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

    /**
     * Sets the time from the given <code>Calendar</code>, miliseconds are
     * ignored and set to 0.
     * 
     * @param calendar
     *                The <code>Calendar</code> with the date that shall be
     *                set.
     */
    public void setDate(Calendar calendar) {
	if (calendar == null) {
	    throw new NullPointerException("calendar");
	}
	date_ = new Date((calendar.getTime().getTime() / 1000) * 1000);

	setString0(toString(date_));
    }

    /**
     * Sets the time from the given Date instance, miliseconds are ignored and
     * set to 0.
     * 
     * @param date
     *                The Date.
     */
    public void setDate(Date date) {
	if (date == null) {
	    throw new NullPointerException("date");
	}
	date_ = new Date((date.getTime() / 1000) * 1000);

	setString0(toString(date_));
    }

    public static void main(String[] argv) {
	ASN1UTCTime gt;
	String s;
	int n;

	try {
	    gt = new ASN1UTCTime();
	    s = gt.toString();

	    System.out.println("Today: " + s);

	    for (n = 0; n < argv.length; n++) {
		gt = new ASN1UTCTime(argv[n]);
		s = gt.toString();

		System.out.println("Date: " + gt.getDate());
	    }
	} catch (Exception e) {
	    e.printStackTrace();
	}
    }

}
