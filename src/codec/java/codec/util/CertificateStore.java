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

import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import codec.x501.BadNameException;
import codec.x501.Name;

/**
 * This class wraps around regular <code>KeyStore</code> instances and
 * supports retrieval of certificates in it by means of the
 * {@link CertificateSource CertificateSource} interface.
 * 
 * @author Volker Roth
 * @version "$Id: CertificateStore.java,v 1.4 2000/12/06 17:47:34 vroth Exp $"
 */
public class CertificateStore extends Object implements CertificateSource {
    /**
     * The cached certificates indexed by their subject names.
     */
    protected Map sdnIdx_ = new HashMap();

    /**
     * The cached certificates indexed by their issuer names and serial numbers.
     */
    protected Map isnIdx_ = new HashMap();

    /**
     * Creates an instance that loads certificates from the given
     * <code>KeyStore</code>.
     * 
     * @param keystore
     *                The <code>KeyStore</code> to load certificates from.
     * @throws KeyStoreException
     *                 if a certificate could not be retrieved from the
     *                 <code>KeyStore</code>.
     */
    public CertificateStore(KeyStore keystore) throws KeyStoreException {
	init(keystore);
    }

    /**
     * Creates an instance that loads certificates from the given
     * <code>Collection</code>.
     * 
     * @param c
     *                The <code>Collection</code> to load certificates from.
     */
    public CertificateStore(Collection c) {
	init(c);
    }

    /**
     * Initializes this instance. Only X.509 certificates are cached and can be
     * retrieved since only those are known to have issuers and subjects and
     * serial numbers.
     */
    protected void init(KeyStore keystore) throws KeyStoreException {
	Enumeration e;
	String alias;

	if (keystore == null) {
	    throw new NullPointerException("KeyStore");
	}
	for (e = keystore.aliases(); e.hasMoreElements();) {
	    alias = (String) e.nextElement();

	    try {
		addCert((X509Certificate) keystore.getCertificate(alias));
	    } catch (ClassCastException ex) {
		/* Ignore, we deal only with X.509 certificates */
	    }
	}
    }

    /**
     * Initializes this instance. Only X.509 certificates are cached and can be
     * retrieved since only those are known to have issuers and subjects and
     * serial numbers.
     */
    protected void init(Collection c) {
	Iterator i;

	if (c == null) {
	    throw new NullPointerException("Collection");
	}
	for (i = c.iterator(); i.hasNext();) {
	    try {
		addCert((X509Certificate) i.next());
	    } catch (ClassCastException e) {
		/* Ignore, we deal only with X.509 certificates */
	    }
	}
    }

    private void addCert(X509Certificate cert) {
	IdxKey entry;
	Object obj;
	List list;

	if (cert == null) {
	    return;
	}
	entry = new IdxKey(cert.getSubjectDN());
	obj = sdnIdx_.get(entry);

	if (obj != null) {
	    if (obj instanceof List) {
		list = (List) obj;
	    } else {
		list = new ArrayList(3);
		list.add(obj);

		sdnIdx_.put(entry, list);
	    }
	    list.add(cert);
	} else {
	    sdnIdx_.put(entry, cert);
	}
	entry = new IdxKey(cert.getIssuerDN(), cert.getSerialNumber());

	isnIdx_.put(entry, cert);
    }

    /**
     * This method retrieves a certificate based on the distinguished name of
     * the certificate's issuer as well as its serial number, as assigned by the
     * issuer.
     * 
     * @param issuer
     *                The issuer distinguished name.
     * @param serial
     *                The serial number.
     * @return The certificate or <code>null</code> if it is not found.
     */
    public X509Certificate getCertificate(Principal issuer, BigInteger serial) {
	return (X509Certificate) isnIdx_.get(new IdxKey(issuer, serial));
    }

    /**
     * @return An <code>Iterator</code> of all known certificates with the
     *         given subject DN.
     * @param subject
     *                The subject DN of the certificate that should be
     *                retrieved.
     * @see CertificateIterator
     */
    public Iterator certificates(Principal subject) {
	return certificates(subject, CertificateSource.ALL);
    }

    /**
     * @return An <code>Iterator</code> of all known certificates with the
     *         given subject DN that match at least one of the given key usage
     *         bits.
     * @param subject
     *                The subject DN of the certificate that should be
     *                retrieved. A value of <code>null</code> matches every
     *                subject DN.
     * @param keyUsage
     *                The mask of key usage bits; at least one of these bits
     *                must be set in the key usage extension of matching
     *                certificates. A value of 0 disables key usage checking.
     * @see CertificateIterator
     */
    public Iterator certificates(Principal subject, int keyUsage) {
	Object obj;
	List list;

	obj = sdnIdx_.get(new IdxKey(subject));

	if (obj == null) {
	    return Collections.EMPTY_LIST.iterator();
	}
	if (obj instanceof X509Certificate) {
	    list = new ArrayList(1);
	    list.add(obj);
	} else {
	    list = (List) obj;
	}
	return new CertificateIterator(subject, keyUsage, list.iterator());
    }

    /**
     * This class represents an entry in the map that maps subject, issuer and
     * serial number info to an alias.
     */
    public class IdxKey extends Object {
	/**
	 * The serial number
	 */
	protected BigInteger serial_;

	/**
	 * The issuer name.
	 */
	protected String issuer_;

	/**
	 * The subject name.
	 */
	protected String subject_;

	/**
	 * Creates an instance with the given issuer name and serial number.
	 * 
	 * @param issuer
	 *                The issuer name.
	 * @param serial
	 *                The serial number.
	 * @throws IllegalArgumentException
	 *                 if the given <code>Principal</code> cannot be
	 *                 parsed into a <code>Name</code>.
	 */
	public IdxKey(Principal issuer, BigInteger serial) {
	    Name name;

	    /*
	     * Sun's implementation of the DN Principal SUCKS!!! Its equals(..)
	     * method screws up, presumably does comparisons of RDNs only in the
	     * order in which they appear in the DN. In order to get a
	     * normalized string I have to do encoding plus decoding of names,
	     * and I have to cope with a potential parsing error.
	     */
	    try {
		name = new Name(issuer.getName(), -1);
		issuer_ = name.toString();
	    } catch (BadNameException e) {
		throw new IllegalArgumentException(e.getMessage());
	    }
	    serial_ = serial;
	}

	/**
	 * Creates an instance with the given subject name.
	 * 
	 * @param subject
	 *                The subject.
	 * @throws IllegalArgumentException
	 *                 if the given <code>Principal</code> cannot be
	 *                 parsed into a <code>Name</code>.
	 */
	public IdxKey(Principal subject) {
	    Name name;

	    /*
	     * Sun's implementation of the DN Principal SUCKS!!! See above for
	     * an explanation of this rant.
	     */
	    try {
		name = new Name(subject.getName(), -1);
		subject_ = name.toString();
	    } catch (BadNameException e) {
		throw new IllegalArgumentException(e.getMessage());
	    }
	}

	/**
	 * Compares two entries for equality. Two entries are equal if all
	 * parameters that are not <code>null</code> in either instance are
	 * equal. The parameters are the subject, issuer and serial number
	 * information.
	 * 
	 * @return <code>true</code> iff both instances are equal.
	 */
	public boolean equals(Object o) {
	    IdxKey e;

	    if (o == this) {
		return true;
	    }
	    if (o == null || !(o instanceof IdxKey)) {
		return false;
	    }
	    e = (IdxKey) o;

	    if (issuer_ != null || e.issuer_ != null) {
		if (issuer_ == null || e.issuer_ == null) {
		    return false;
		}
		if (!issuer_.equals(e.issuer_)) {
		    return false;
		}
	    }
	    if (subject_ != null || e.subject_ != null) {
		if (subject_ == null || e.subject_ == null) {
		    return false;
		}
		if (!subject_.equals(e.subject_)) {
		    return false;
		}
	    }
	    if (serial_ != null || e.serial_ != null) {
		if (serial_ == null || e.serial_ == null) {
		    return false;
		}
		if (!serial_.equals(e.serial_)) {
		    return false;
		}
	    }
	    return true;
	}

	/**
	 * Returns the hash code of this instance. The hash code is computed
	 * simply by exclusive or-ing the hash codes of all the parameters of
	 * this instance.
	 */
	public int hashCode() {
	    int h = 0;

	    if (issuer_ != null) {
		h = h ^ issuer_.hashCode();
	    }
	    if (subject_ != null) {
		h = h ^ subject_.hashCode();
	    }
	    if (serial_ != null) {
		h = h ^ serial_.hashCode();
	    }
	    return h;
	}

    }
}
