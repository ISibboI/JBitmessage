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
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.Iterator;

/**
 * Classes implementing this interface are meant to retrieve certificates based
 * on either an issuer distinguished name and a serial number or the subject
 * distinguished name.
 * <p>
 * 
 * Distinguished names are principals and should implement the
 * {@link Principal Principal} interface.
 * <p>
 * 
 * Digital signatures in general should include information on the principal who
 * did the signing, as well as on the the principal who attests the validity of
 * the relationship between the claimed identity and the public key that can be
 * used to verify the signature.
 * <p>
 * 
 * Since each subject may own several certificates, for a given signature the
 * corresponding certificate may not reliably be identified by its subject's
 * identity. In that case, the certificate needs to be retrieved based on:
 * <ul>
 * <li> the principal who issued the certificate, and
 * <li> the serial number of the certificate
 * </ul>
 * If, however, a message should be sent to a principal whose certificate is not
 * known, but its distinguished name, then retrieval must be based on the
 * distinguished name of that principal (for instance requesting the certificate
 * from an LDAP directory service).
 * <p>
 * 
 * In principle, the java.security.KeyStore is the first choice for certificate
 * storage. However, this interface does not support retrieval based on
 * distinguished names, but based on an <i>alias</i> that is not globally
 * unique and cannot be bound to the certificate.
 * <p>
 * 
 * This interface may also be used for LDAP based certificate services. In other
 * words, a service that retrieves certificates based on a X.501 or RFC1779
 * distinguished name from a LDAP directory service.
 * 
 * @author Volker Roth
 * @version "$Id: CertificateSource.java,v 1.4 2001/02/25 15:06:31 vroth Exp $"
 * @see java.security.cert.CertificateException
 */
public interface CertificateSource {
    /**
     * Matches all key usage bits including all-zero key usage bits (effectively
     * disables checking of key usage bits).
     */
    public static final int ALL = 0x00;

    /**
     * Matches certificates with the <code>nonRepudiation
     * </code> bit set.
     */
    public static final int NON_REPUDIATION = 0x02;

    /**
     * Matches certificates with the <code>keyEncipherment
     * </code> bit set.
     */
    public static final int KEY_ENCIPHERMENT = 0x04;

    /**
     * Matches certificates with the <code>dataEncipherment
     * </code> bit set.
     */
    public static final int DATA_ENCIPHERMENT = 0x08;

    /**
     * Matches certificates with the <code>keyAgreement
     * </code> bit set.
     */
    public static final int KEY_AGREEMENT = 0x10;

    /**
     * Matches certificates with the <code>keyCertSign
     * </code> bit set.
     */
    public static final int KEY_CERT_SIGN = 0x20;

    /**
     * This method retrieves a certificate based on the distinguished name of
     * the certificate's issuer as well as its serial number, as assigned by the
     * issuer.
     * 
     * @return The certificate or <code>null</code> if it is not found.
     * @param issuer
     *                The issuer distinguished name.
     * @param serial
     *                The serial number.
     */
    public X509Certificate getCertificate(Principal issuer, BigInteger serial);

    /**
     * Retrieves certificates based on the distinguished name of the
     * certificate's subject.
     * 
     * @return An <code>Iterator</code> of all known certificates with the
     *         given subject DN.
     * @param subject
     *                The subject DN of the certificate that should be
     *                retrieved.
     * @see CertificateIterator
     */
    public Iterator certificates(Principal subject);

    /**
     * Retrieves certificates based on the distinguished name of the
     * certificate's subject and a number of key usage bits.
     * 
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
    public Iterator certificates(Principal subject, int keyUsage);
}
