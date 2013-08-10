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
package codec.x509.extensions;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import codec.asn1.ASN1Exception;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1OctetString;
import codec.asn1.ASN1Sequence;
import codec.asn1.Decoder;
import codec.x509.AlgorithmIdentifier;
import codec.x509.X509Extension;

/**
 * id-sigi-at-certHash OBJECT IDENTIFIER ::= { 1 3 36 8 3 13 }
 * 
 * <pre>
 * certHash EXTENSION ::= {
 *   SYNTAX CertHashSyntax
 *   IDENTIFIED BY id-sigi-at-certHash
 * }
 * CertHashSyntax ::= SEQUENCE {
 *   hashAlgorithm AlgorithmIdentifier,
 *   certificateHash OCTET STRING
 * }
 * </pre>
 * 
 * @author Volker Roth
 * @version "$Id: CertHashExtension.java,v 1.1 2004/08/16 13:31:37 pebinger Exp $"
 */
public class CertHashExtension extends X509Extension {
    public static final String DEFAULT_HASH_ALG = "SHA1";

    public static final String EXTENSION_OID = "1.3.36.8.3.13";

    private ASN1Sequence syntax_;
    private AlgorithmIdentifier hashAlgorithm_;
    private ASN1OctetString certificateHash_;

    /**
     * Creates an instance ready for decoding.
     */
    public CertHashExtension() throws ASN1Exception,
	    CertificateEncodingException {
	setOID(new ASN1ObjectIdentifier(EXTENSION_OID));
	setCritical(false);

	syntax_ = new ASN1Sequence(2);
	hashAlgorithm_ = new AlgorithmIdentifier();
	certificateHash_ = new ASN1OctetString();

	syntax_.add(hashAlgorithm_);
	syntax_.add(certificateHash_);

	setValue(syntax_);
    }

    /**
     * Creates an instance with the hash of the given certificate. The hash is
     * computed with the default hash function {@link #DEFAULT_HASH_ALG
     * DEFAULT_HASH_ALG}.
     */
    public CertHashExtension(X509Certificate cert) throws ASN1Exception,
	    GeneralSecurityException {
	this(cert, DEFAULT_HASH_ALG);
    }

    /**
     * Creates an instance with a hash of the given certificate where the hash
     * is computed with the given hash algorithm.
     * 
     * @throws NoSuchAlgorithmException
     *                 if the given algorithm is not available.
     * @throws CertificateEncodingException
     *                 if the given certificate cannot be encoded correctly.
     * @throws GeneralSecurityException
     *                 if there is another security related error condition.
     * @throws ASN1Exception
     *                 hardly ever, this exception must be declared basically
     *                 because it is declared in the constructor of the super
     *                 class.
     */
    public CertHashExtension(X509Certificate cert, String alg)
	    throws ASN1Exception, GeneralSecurityException {
	this(cert.getEncoded(), alg);
    }

    /**
     * Creates an instance with a hash of the given encoded certificate where
     * the hash is computed with the given hash algorithm.
     * 
     * @throws NoSuchAlgorithmException
     *                 if the given algorithm is not available.
     * @throws GeneralSecurityException
     *                 if there is another security related error condition.
     * @throws ASN1Exception
     *                 hardly ever, this exception must be declared basically
     *                 because it is declared in the constructor of the super
     *                 class.
     */
    public CertHashExtension(byte[] cert, String alg) throws ASN1Exception,
	    GeneralSecurityException {
	if (cert == null) {
	    throw new NullPointerException("cert");
	}
	AlgorithmIdentifier aid;
	MessageDigest dig;
	byte[] buf;

	aid = new AlgorithmIdentifier(alg);
	dig = MessageDigest.getInstance(alg);
	buf = dig.digest(cert);

	syntax_ = new ASN1Sequence(2);
	hashAlgorithm_ = aid;
	certificateHash_ = new ASN1OctetString(buf);

	syntax_.add(hashAlgorithm_);
	syntax_.add(certificateHash_);

	setOID(new ASN1ObjectIdentifier(EXTENSION_OID));
	setCritical(false);
	setValue(syntax_);
    }

    public void decode(Decoder dec) throws ASN1Exception, IOException {
	super.decode(dec);
	super.decodeExtensionValue(syntax_);
    }

    public AlgorithmIdentifier getHashAlgorithmID() {
	return hashAlgorithm_;
    }

    public String getHashAlgorithmName() {
	return hashAlgorithm_.getAlgorithmName();
    }

    /**
     * @return <code>true</code> if the hash of the given certificate equals
     *         the hash stored in this structure.
     */
    public boolean verify(X509Certificate cert)
	    throws NoSuchAlgorithmException, CertificateEncodingException {
	return verify(cert.getEncoded());
    }

    /**
     * @return <code>true</code> if the hash of the given certificate equals
     *         the hash stored in this structure.
     */
    public boolean verify(byte[] cert) throws NoSuchAlgorithmException {
	MessageDigest dig;
	String alg;
	byte[] buf;

	alg = hashAlgorithm_.getAlgorithmName();

	if (alg == null) {
	    throw new NoSuchAlgorithmException(hashAlgorithm_.getAlgorithmOID()
		    .toString());
	}
	dig = MessageDigest.getInstance(alg);
	buf = dig.digest(cert);

	return Arrays.equals(buf, certificateHash_.getByteArray());
    }

}
