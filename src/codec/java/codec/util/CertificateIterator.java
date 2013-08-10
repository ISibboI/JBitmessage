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
package codec.util;

import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.NoSuchElementException;

import codec.x501.BadNameException;
import codec.x501.Name;

/**
 * This <code>Iterator</code> wraps around the <code>
 * Iterator</code> of e.g.
 * a <code>List</code> of certificates and filters certificates that match
 * particular parameters such as a given subject DN and/or key usage bits.
 * 
 * @author Volker Roth
 * @version "$Id: CertificateIterator.java,v 1.4 2000/12/06 17:47:34 vroth Exp $"
 */
public class CertificateIterator extends Object implements Iterator {
    /**
     * The certificate that is returned next.
     */
    private X509Certificate nextCert_;

    /**
     * The subject DN to compare with.
     */
    private Principal dn_;

    /**
     * The index of required key usage bits; at least one bit must be set in a
     * matching certificate.
     */
    private int[] usage_;

    /**
     * The <code>Iterator</code> of the certificates in the
     * <code>isnIdx_</code>.
     */
    private Iterator i_;

    /**
     * Creates an instance which iterates certificates with the given subject DN
     * and at least one of the given key usage extension bits set (unless
     * <code>usage</code> is 0 which acts as a wildcard that matches any key
     * key usage bits as well as no key usage bits at all).
     * 
     * @param subject
     *                The subject DN that must be matched. If
     *                <code>subject</code> is <code>null</code> then any
     *                subject DN is matched.
     * @param usage
     *                The key usage bits that must be matched. At least one of
     *                the given bits must be <code>true
     *   </code> for a match.
     *                The bits in <code>usage</code> are alternatives and
     *                represent an <code>OR</code> query. In order to query
     *                for key usage bit <i>n</i>, bit number <i>n</i> must be
     *                set in <code>usage
     *   </code>. If <code>usage</code> is 0
     *                then no key usage bits are checked (hence 0 acts as a
     *                wildcard that matches any key usage bit including no bits
     *                at all).
     * @param i
     *                The <code>Iterator</code> that is wrapped by this
     *                instance.
     * @throws NullPointerException
     *                 if <code>i</code> is <code>null</code>.
     * @throws IllegalArgumentException
     *                 if <code>subject
     *   </code> is not
     *                 <code>null</<ode> and cannot be parsed
     *   into a <code>Name</code>.
     */
    public CertificateIterator(Principal subject, int usage, Iterator i) {
	int n;
	int k;
	int m;

	if (i == null) {
	    throw new NullPointerException("No Iterator given!");
	}
	if (usage != 0) {
	    for (n = 0, k = usage; k != 0;) {
		if ((k & 1) > 0) {
		    n++;
		}
		k = k >>> 1;
	    }
	    usage_ = new int[n];

	    for (m = 0, k = usage; k != 0; m++) {
		if ((k & 1) > 0) {
		    usage_[--n] = m;
		}
		k = k >>> 1;
	    }
	}
	i_ = i;

	try {
	    if (subject != null) {
		dn_ = new Name(subject.getName(), -1);
	    }
	} catch (BadNameException e) {
	    throw new IllegalArgumentException(e.getMessage());
	}
    }

    public boolean hasNext() {
	X509Certificate cert;
	boolean[] usage;
	int k;
	int n;

	if (nextCert_ != null) {
	    return true;
	}
	while (i_.hasNext()) {
	    cert = (X509Certificate) i_.next();

	    /*
	     * Ignore dn_ if it is null, treat it like a wildcard.
	     */
	    if (dn_ != null && !dn_.equals(cert.getSubjectDN())) {
		continue;
	    }
	    /*
	     * If no key usage bit indexes are set then we accept the
	     * certificate without further checking (wildcard case).
	     */
	    if (usage_ == null) {
		nextCert_ = cert;
		return true;
	    }
	    /*
	     * Check if at least one required key usage bit is true.
	     */
	    usage = cert.getKeyUsage();

	    /*
	     * Check if no key usage is set in the cert. Since we checked for
	     * usage_ == null already above, we have to go on and find another
	     * cert.
	     */
	    if (usage == null) {
		continue;
	    }
	    for (n = usage_.length - 1; n >= 0; n--) {
		k = usage_[n];

		if (k >= usage.length) {
		    break;
		}
		if (usage[k]) {
		    nextCert_ = cert;
		    return true;
		}
	    }
	}
	return false;
    }

    public Object next() throws NoSuchElementException {
	X509Certificate cert;

	if (!hasNext()) {
	    throw new NoSuchElementException("No more certificates!");
	}
	cert = nextCert_;
	nextCert_ = null;

	return cert;
    }

    /**
     * @throws UnsupportedOperationException
     *                 always.
     */
    public void remove() {
	throw new UnsupportedOperationException("Not allowed!");
    }
}
