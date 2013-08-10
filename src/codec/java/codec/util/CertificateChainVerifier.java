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

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/**
 * Provides utility methods for managing certificates. For instance verification
 * of certificate chains and similar recurring tasks.
 * 
 * For each certificate that is verified the following constraints are checked:
 * <ul>
 * <li> Validity period.
 * <li> Key usage bits (<code>keyCertSign</code>(5)).
 * <li> Basic constraints (chain length constraints).
 * <li> Issuer to subject chaining.
 * <li> Signature validity.
 * </ul>
 * Future revisions of this class might also provide automatic checking of
 * certificate revocation lists.
 * 
 * @author Volker Roth
 * @version "$Id: CertificateChainVerifier.java,v 1.2 2000/12/06 17:47:34 vroth
 *          Exp $"
 */
public class CertificateChainVerifier extends Object {
    /**
     * The <code>CertificateSource</code> with the trusted CA certificates.
     */
    private CertificateSource trusted_;

    /**
     * Creates an instance.
     * 
     * @param trusted
     *                The <code>CertifiateSource</code> with the trusted CA
     *                certificates.
     */
    public CertificateChainVerifier(CertificateSource trusted) {
	if (trusted == null) {
	    throw new NullPointerException("Trusted cert source");
	}
	trusted_ = trusted;
    }

    /**
     * Verifies the given certificate. The chain of certificate issuers is
     * traced using the certificates in <code>other
     * </code> as well as the
     * trusted certificates that were passed to the constructor of this
     * instance. The chain must end in a trusted certificate.
     * <p>
     * 
     * In case of mismatches or errors this method aborts with an exception. In
     * the case of success it completes normally.
     * 
     * @param cert
     *                The certificate that is verified.
     * @param other
     *                A <code>CertificateSource</code> with supplementary
     *                certificates. These certificates are not treated as
     *                trusted certificates. Hence they do not complete a
     *                certificate chain.
     * @throws GeneralSecurityException
     *                 if something goes wrong. Reasons can be expired
     *                 certificates, invalid signatures, unavailable algorithms,
     *                 and more. The exact cause is signalled by the actual type
     *                 of exception being thrown. For instance, a bad signature
     *                 is signalled by means of a
     *                 <code>SignatureException</code>.
     */
    public void verify(X509Certificate cert, CertificateSource other)
	    throws GeneralSecurityException {
	X509Certificate issuerCert;
	X509Certificate origCert;
	int chainLength;
	Set verified;

	if (cert == null) {
	    throw new NullPointerException("Certificate");
	}
	verified = new HashSet(8);
	origCert = cert;

	/*
	 * The invariant is that valid certificates enter the loop. The validity
	 * of issuer certs is checked within the loop.
	 */
	cert.checkValidity();

	/*
	 * Repeat ad infinitum unless we hit a valid trusted CA certificate.
	 */
	for (chainLength = 0; true; chainLength++) {
	    /*
	     * Check for vicious cycles in the certificate chain.
	     */
	    if (verified.contains(cert)) {
		throw new CertificateException("Circular chain!");
	    }
	    issuerCert = checkIssuer(cert, trusted_, chainLength);

	    /*
	     * Did we hit a trusted cert? This is the exit point of the method
	     * for successful verification.
	     */
	    if (issuerCert != null) {
		return;
	    }
	    issuerCert = checkIssuer(cert, other, chainLength);

	    /*
	     * If there is a matching valid issuer cert in the 'other' cert
	     * source then we go on and try to match that one against the
	     * trusted certs. If there isn't then we boil out the hard way.
	     */
	    if (issuerCert == null) {
		fail("Untrusted certificate: %s", origCert);
	    }
	    cert = issuerCert;
	}
    }

    /**
     * Verifies the given certificate against the trusted certificates passed to
     * the constructor of this instance. If the verification succeeds then this
     * method completes normally. Otherwise, an exception is thrown.
     * 
     * @throws GeneralSecurityException
     *                 if the verification fails. The exact cause is signalled
     *                 by means of the exception sub-type.
     */
    public void verify(X509Certificate cert) throws GeneralSecurityException {
	if (cert == null) {
	    throw new NullPointerException("Certificate");
	}
	/*
	 * The invariant is that valid certificates enter the loop. The validity
	 * of issuer certs is checked within the loop.
	 */
	cert.checkValidity();

	if (checkIssuer(cert, trusted_, 0) == null) {
	    fail("Untrusted certificate: %s", cert);
	}
	return;
    }

    /**
     * Verifies the given certificate chain. In case of a successful
     * verification this method completes normally. Otherwise, it throws an
     * exception. In order for the verification to succeed, at least one
     * certificate in it must be a trusted certificate and the chain must be
     * valid up to the trusted certificate.
     * 
     * @param chain
     *                The chain of certificates to be verified. The chain starts
     *                at index 0. Each certificate but the first must
     *                authenticate the preceeding certificate in the chain.
     * @throws GeneralSecurityException
     *                 if the verification fails.
     */
    public void verifyChain(X509Certificate[] chain)
	    throws GeneralSecurityException {
	if (chain == null) {
	    throw new NullPointerException("Chain");
	}
	X509Certificate issuerCert;
	X509Certificate cert;
	boolean[] usage;
	int maxChainLength;
	int n;

	if (chain.length < 1 || chain[0] == null) {
	    throw new CertificateException(
		    "Chain is empty or element 0 is null!");
	}
	cert = chain[0];
	cert.checkValidity();

	if (isTrusted(cert)) {
	    return;
	}
	for (n = 1; n < chain.length; n++) {
	    issuerCert = chain[n];

	    if (issuerCert == null) {
		throw new CertificateException("Null cert at " + n);
	    }
	    issuerCert.checkValidity();

	    /*
	     * Check key usage extension bits.
	     */
	    usage = issuerCert.getKeyUsage();

	    if (usage == null || usage.length < 6 || !usage[5]) {
		fail("Not a key signing certificate: %s", issuerCert);
	    }
	    /*
	     * Check basic constraints.
	     */
	    maxChainLength = issuerCert.getBasicConstraints();

	    if (maxChainLength < 0) {
		fail("Chain contains non CA cert: %s", issuerCert);
	    }
	    if (maxChainLength + 1 < n) {
		fail("Chain too long at %s", issuerCert);
	    }
	    if (!cert.getIssuerDN().equals(issuerCert.getSubjectDN())) {
		fail("Issuer vs. subject mismatch in cert: %s", cert);
	    }
	    cert.verify(issuerCert.getPublicKey());

	    /*
	     * Check if we already found a trusted cert.
	     */
	    if (isTrusted(issuerCert)) {
		return;
	    }
	}
	fail("Chain of %s is not trusted!", chain[0]);
    }

    /**
     * Checks if the given certificate is a trusted certificate.
     * 
     * @param cert
     *                The certificate to check.
     * @return <code>true</code> if <code>cert</code> is a trusted
     *         certificate and <code>false</code> otherwise.
     */
    public boolean isTrusted(X509Certificate cert) {
	X509Certificate trustedCert;

	if (cert == null) {
	    return false;
	}
	trustedCert = trusted_.getCertificate(cert.getIssuerDN(), cert
		.getSerialNumber());

	if (trustedCert == null) {
	    return false;
	}
	return trustedCert.equals(cert);
    }

    /**
     * Retrieves the potential issuer certificates of the given certificate from
     * <code>certSource</code> and does the appropriate verification steps. In
     * case of success, the issuer certificate is returned and <code>null</code>
     * otherwise.
     * 
     * @param cert
     *                The certificate to check, and whose issuing certificate
     *                shall be returned.
     * @param certSource
     *                The <code>CertificateSource</code> with the certificates
     *                that are able to authenticate <code>cert</code>.
     * @param chainLength
     *                The current length of the chain. This value is required
     *                for testing the basic constraints on the issuing
     *                certificates. If <code>
     *   cert</code> is an end-user
     *                certificate then <code>
     *   chainLength</code> must be 0.
     * @return The issuing certificate or <code>null</code> is none could be
     *         found in <code>certSource</code>.
     * @throws GeneralSecurityException
     *                 if the verification fails.
     */
    private X509Certificate checkIssuer(X509Certificate cert,
	    CertificateSource certSource, int chainLength)
	    throws GeneralSecurityException {
	X509Certificate issuerCert;
	Iterator i;
	int maxChainLength;

	/*
	 * There might be more than one matching issuer certificate, e.g. if the
	 * issuer is cross-certified with multiple other CAs.
	 */
	i = certSource.certificates(cert.getIssuerDN(),
		CertificateSource.KEY_CERT_SIGN);

	while (i.hasNext()) {
	    issuerCert = (X509Certificate) i.next();

	    /*
	     * Step 1: Check if the issuer cert is still valid. Key usage bits
	     * were checked implicitly by the iterator.
	     */
	    try {
		issuerCert.checkValidity();
	    } catch (CertificateException e) {
		System.err.println("Warning, trusted cert is not current:\n"
			+ issuerCert);

		continue;
	    }
	    /*
	     * Step 2: Verify the certificate, this might fail because we got a
	     * wrong issuer certificate with a key type that doesn't match.
	     * However, this shouldn't happen in practice because CAs should use
	     * different distinguished names for different certificates.
	     */
	    try {
		cert.verify(issuerCert.getPublicKey());
	    } catch (InvalidKeyException e) {
		continue;
	    }
	    /*
	     * Step 3: Check basic constraints. The current chain length must
	     * not be longer than certified in the current issuer cert.
	     */
	    maxChainLength = issuerCert.getBasicConstraints();

	    if (maxChainLength < 0) {
		fail("Trusted cert is not a CA cert: %s", issuerCert);
	    }
	    if (maxChainLength < chainLength) {
		fail("Certificate chain too long (" + maxChainLength + " > "
			+ chainLength + ") at %s", issuerCert);
	    }
	    return issuerCert;
	}
	return null;
    }

    /**
     * Throws a <code>CertificateException</code> with the given error
     * message. If <code>message</code> contains &quot;%s&quot; then the first
     * occurence of this substring is replaced by a string that gives the issuer
     * DN and serial number of <code>cert</code>. No <code>null</code>
     * arguments are accepted.
     * 
     * @param message
     *                The message of the exception to be thrown.
     * @param cert
     *                The certificate whose issuer DN and serial number shall be
     *                substituted into <code>
     *   message</code>.
     * @throws CertificateException
     *                 always.
     */
    private void fail(String message, X509Certificate cert)
	    throws CertificateException {
	int n;

	n = message.indexOf("%s");

	if (n >= 0) {
	    message = message.substring(0, n) + "issuer=\""
		    + cert.getIssuerDN().getName() + "\", serial="
		    + cert.getSerialNumber() + message.substring(n + 2);
	}
	throw new CertificateException(message);
    }

}
