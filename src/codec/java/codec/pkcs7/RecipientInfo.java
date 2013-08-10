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
package codec.pkcs7;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import codec.asn1.ASN1Integer;
import codec.asn1.ASN1OctetString;
import codec.asn1.ASN1Sequence;
import codec.util.JCA;
import codec.x501.BadNameException;
import codec.x501.Name;
import codec.x509.AlgorithmIdentifier;
import codec.x509.SubjectPublicKeyInfo;

/**
 * This class represents a PKCS#7 RecipientInfo structure. It is defined as
 * follows:
 * 
 * <pre>
 * RecipientInfo ::= SEQUENCE {
 *   version Version, -- 0 for version 1.5 of PKCS#7
 *   issuerAndSerialNumber IssuerAndSerialNumber,
 *   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
 *   encryptedKey EncryptedKey
 * }
 * EncryptedKey ::= OCTET STRING
 * KeyEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
 * </pre>
 * 
 * For completeness, we also present the structures referenced in the
 * RecipientInfo structure.
 * 
 * <pre>
 * IssuerAndSerialNumber ::= SEQUENCE {
 *   issuer Name,
 *   serialNumber CertificateSerialNumber
 * }
 * CertificateSerialNumber ::= INTEGER
 * </pre>
 * 
 * This class provides methods to create a RecipientInfo structure from a
 * certificate and a BEK. BEK stands for <i>Bulk Encryption Key</i>. The BEK is
 * in general a symmetric key that is used to encrypt bulk data. The BEK is then
 * encrypted with the public key of the recipient of the bulk data. The public
 * key is sometimes called the <i>Key Encryption Key</i> (KEK).
 * <p>
 * 
 * The BEK can be retrieved easily from instances of this structure as long as
 * the algorithm of the DEK is known. This information is not stored in this
 * class but in the {@link EncryptedContentInfo EncryptedContentInfo} structure,
 * which contains RecipientInfo structures for each intended recipient of the
 * bulk data.
 * <p>
 * 
 * This class is completely JCE integrated. It determines the instances to use
 * for encrypting and decrypting based on the OID contained in its instances.
 * The OID are mapped to algorithm names and vice versa by the {@link JCA JCA}
 * class, which requires appropriate aliases to be defined for algorithm
 * implementations as described in the JCE documentation. If your installed
 * providers do not support the aliasing scheme then request such support from
 * your provider's supplier, or add a provider that properly defines the aliases
 * (aliases are global to all providers).
 * 
 * @author Volker Roth
 * @version "$Id: RecipientInfo.java,v 1.6 2007/08/30 08:45:05 pebinger Exp $"
 */
public class RecipientInfo extends ASN1Sequence {
    /**
     * The version number of this RecipientInfo.
     */
    protected ASN1Integer version_;

    /**
     * The issuer name.
     */
    protected Name issuer_;

    /**
     * The serial number.
     */
    protected ASN1Integer serial_;

    /**
     * The {@link AlgorithmIdentifier KeyEncryptionAlgorithmIdentifier}.
     */
    protected AlgorithmIdentifier cAlg_;

    /**
     * The encrypted key.
     */
    protected ASN1OctetString ekey_;

    /**
     * The default constructor.
     */
    public RecipientInfo() {
	super(4);

	ASN1Sequence seq;

	/* Global structure and Version */
	version_ = new ASN1Integer(0);
	add(version_);

	/* Issuer and serial number */
	issuer_ = new Name();
	serial_ = new ASN1Integer();

	seq = new ASN1Sequence(2);
	seq.add(issuer_);
	seq.add(serial_);
	add(seq);

	/* Key Encryption Algorithm Identifier */
	cAlg_ = new AlgorithmIdentifier();
	add(cAlg_);

	/* Encrypted Key */
	ekey_ = new ASN1OctetString();
	add(ekey_);
    }

    /**
     * This method calls initializes this structure with the given arguments.
     * The given <code>bek</code> is encrypted with the given public key. The
     * algorithm to use is determined by means of the OID in the
     * {@link AlgorithmIdentifier AlgorithmIdentifier} that is embedded in the
     * public key's encoding. Decoding is done using a
     * {@link SubjectPublicKeyInfo SubjectPublicKeyInfo} instance.
     * 
     * @param cert
     *                The certificate to use for encrypting the given
     *                <code>bek</code>.
     * @param bek
     *                The bulk encryption key.
     */
    public RecipientInfo(X509Certificate cert, Key bek)
	    throws BadNameException, GeneralSecurityException {
	super(4);

	// FIXME Add and adjust saftey check for new Name implementation of
	// Fraunhofer IGD
	// if(!Name.defaultEncoding_)
	// throw new BadNameException("Use the constructor that explicitly set
	// the Name encoding type");

	SubjectPublicKeyInfo pki;
	AlgorithmIdentifier aid;
	ASN1Sequence seq;
	PublicKey pub;
	Cipher cipher;
	byte[] b;

	if (cert == null || bek == null) {
	    throw new NullPointerException("cert or bulk encryption key");
	}
	/* Global structure and Version */
	version_ = new ASN1Integer(0);
	add(version_);

	/* Issuer and serial number */
	issuer_ = new Name(cert.getIssuerDN().getName(), -1);
	serial_ = new ASN1Integer(cert.getSerialNumber());

	seq = new ASN1Sequence(2);
	seq.add(issuer_);
	seq.add(serial_);
	add(seq);

	/*
	 * Extract algorithm identifier from the public key
	 */
	pub = cert.getPublicKey();
	pki = new SubjectPublicKeyInfo(pub);
	aid = pki.getAlgorithmIdentifier();

	/*
	 * Initialize the cipher instance
	 */
	cipher = Cipher.getInstance(pub.getAlgorithm());
	cipher.init(Cipher.ENCRYPT_MODE, pub);

	/*
	 * Key Encryption Algorithm Identifier
	 */
	cAlg_ = (AlgorithmIdentifier) aid.clone();
	add(cAlg_);

	/*
	 * Encrypt the bulk encryption key. Better safe than sorry - we check
	 * for bad return values from both the key and the cipher. This already
	 * happened and finding errors like this takes ages!
	 */
	b = bek.getEncoded();

	if (b == null || b.length == 0) {
	    throw new InvalidKeyException(
		    "Key returns no or zero length encoding!");
	}
	b = cipher.doFinal(b);

	if (b == null || b.length == 0) {
	    throw new InvalidKeyException("Cipher returned no data!");
	}
	ekey_ = new ASN1OctetString(b);

	add(ekey_);
    }

    /**
     * same as above but with an explicit encoding type
     */
    public RecipientInfo(X509Certificate cert, Key bek, int encType)
	    throws BadNameException, GeneralSecurityException {
	super(4);

	SubjectPublicKeyInfo pki;
	AlgorithmIdentifier aid;
	ASN1Sequence seq;
	PublicKey pub;
	Cipher cipher;
	byte[] b;

	if (cert == null || bek == null) {
	    throw new NullPointerException("cert or bulk encryption key");
	}
	/* Global structure and Version */
	version_ = new ASN1Integer(0);
	add(version_);

	/* Issuer and serial number */
	// der scep hack der funktioniert hat
	// issuer_ = new Name(cert.getIssuerDN().getName(),true);
	issuer_ = new Name(cert.getIssuerDN().getName(), encType);
	serial_ = new ASN1Integer(cert.getSerialNumber());

	seq = new ASN1Sequence(2);
	seq.add(issuer_);
	seq.add(serial_);
	add(seq);

	/*
	 * Extract algorithm identifier from the public key
	 */
	pub = cert.getPublicKey();
	pki = new SubjectPublicKeyInfo(pub);
	aid = pki.getAlgorithmIdentifier();

	/*
	 * Initialize the cipher instance
	 */
	cipher = Cipher.getInstance(pub.getAlgorithm());
	cipher.init(Cipher.ENCRYPT_MODE, pub);

	/*
	 * Key Encryption Algorithm Identifier
	 */
	cAlg_ = (AlgorithmIdentifier) aid.clone();
	add(cAlg_);

	/*
	 * Encrypt the bulk encryption key. Better safe than sorry - we check
	 * for bad return values from both the key and the cipher. This already
	 * happened and finding errors like this takes ages!
	 */
	b = bek.getEncoded();

	if (b == null || b.length == 0) {
	    throw new InvalidKeyException(
		    "Key returns no or zero length encoding!");
	}
	b = cipher.doFinal(b);

	if (b == null || b.length == 0) {
	    throw new InvalidKeyException("Cipher returned no data!");
	}
	ekey_ = new ASN1OctetString(b);

	add(ekey_);
    }

    /**
     * This method returns the encrypted bulk encryption key. The returned byte
     * array is a copy. Modifying it causes no side effects.
     * 
     * @return The encrypted key.
     */
    public byte[] getEncryptedKey() {
	return (byte[]) ekey_.getByteArray().clone();
    }

    /**
     * This method returns the decrypted data encryption key stored in this
     * structure.
     * 
     * @param kdk
     *                The private key decryption key.
     * @param bekalg
     *                The name of the algorithm of the encrypted bulk encryption
     *                key.
     * @throws NoSuchAlgorithmException
     *                 if the OID cannot be mapped onto a registered algorithm
     *                 name.
     */
    public SecretKey getSecretKey(PrivateKey kdk, String bekalg)
	    throws GeneralSecurityException {
	AlgorithmParameters params;
	Cipher cipher;
	String alg;
	byte[] b;

	params = cAlg_.getParameters();
	alg = cAlg_.getAlgorithmOID().toString();
	cipher = Cipher.getInstance(alg);

	if (params == null) {
	    cipher.init(Cipher.DECRYPT_MODE, kdk);
	} else {
	    cipher.init(Cipher.DECRYPT_MODE, kdk, params);
	}
	b = ekey_.getByteArray();

	if (b.length == 0) {
	    throw new InvalidKeyException("No encrypted key available!");
	}
	b = cipher.doFinal(b);

	if (b == null || b.length == 0) {
	    throw new InvalidKeyException("Cipher returned no data!");
	}
	return new SecretKeySpec(b, bekalg);
    }

    /**
     * Returns the issuer name. The returned instance is the one used
     * internally. Modifying it causes side effects.
     * 
     * @return The issuer Name.
     */
    public Principal getIssuer() {
	return issuer_;
    }

    /**
     * Returns the serial number.
     * 
     * @return The serial number.
     */
    public BigInteger getSerialNumber() {
	return serial_.getBigInteger();
    }

    /**
     * This method returns the KeyEncryptionAlgorithmIdentifier. The returned
     * instance is the one used internally. Modifying it causes side effects.
     * 
     * @return The KeyEncryptionAlgorithmIdentifier.
     */
    public AlgorithmIdentifier getAlgorithmIdentifier() {
	return cAlg_;
    }

    /**
     * This method returns the resolved key encryption algorithm name that can
     * be used for requesting JCE Cipher implementations. This method uses
     * {@link JCA JCA}. If the name consists of an OID then either the
     * appropriate algorithms are not supported by the installed JCE Providers
     * or the aliases defined by those Providers are incomplete.
     * 
     * @return The name of the key encryption algorithm that is required for
     *         decrypting the DEK this structure.
     */
    public String getAlgorithm() {
	String c, t;

	c = cAlg_.getAlgorithmOID().toString();
	t = JCA.getName(c);

	if (t != null) {
	    return t;
	}
	return c;
    }

    /**
     * Returns a string representation of this object.
     * 
     * @return The string representation.
     */
    public String toString() {
	StringBuffer buf;

	buf = new StringBuffer();

	buf.append("PKCS#7 RecipientInfo {\n" + "Version   : "
		+ version_.toString() + "\n" + "Issuer    : "
		+ issuer_.getName() + "\n" + "Serial    : "
		+ serial_.toString() + "\n" + "Algorithm : " + getAlgorithm()
		+ "\n" + "Enc. DEK  : " + ekey_.toString() + "\n}");

	return buf.toString();
    }
}
