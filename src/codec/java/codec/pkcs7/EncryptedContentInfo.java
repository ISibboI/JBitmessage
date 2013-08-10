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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.NoSuchElementException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import codec.InconsistentStateException;
import codec.asn1.ASN1Exception;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1OctetString;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1TaggedType;
import codec.asn1.Decoder;
import codec.x501.BadNameException;
import codec.x509.AlgorithmIdentifier;

/**
 * This class represents a <code>EncryptedContentInfo</code> as defined in <a
 * href="http://www.rsa.com/rsalabs/pubs/PKCS/html/pkcs-7.html"> PKCS#7</a>.
 * The ASN.1 definition of this structure is
 * <p>
 * 
 * <pre>
 * EncryptedContentInfo ::= SEQUENCE {
 *   contentType ContentType,
 *   contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
 *   encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL
 * }
 * EncryptedContent ::= OCTET STRING
 * ContentEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
 * </pre>
 * 
 * <p>
 * <code>contentType</code> indicates the type of content embedded in the
 * EncryptedContent. The encryptedContent is optional; if it is not included in
 * this structure then it must be provided by other means (such as a detached
 * file).
 * <p>
 * 
 * PKCS#7 specifies six content types, of which five are supported:
 * {@link Data data}, {@link SignedData signedData},
 * {@link EnvelopedData envelopedData},
 * {@link SignedAndEnvelopedData signedAndEnvelopedData}, and
 * {@link EncryptedData encryptedData}. All of these content types have
 * registered OIDs.
 * <p>
 * 
 * @author Volker Roth
 * @author Markus Tak
 * @version "$Id: EncryptedContentInfo.java,v 1.9 2007/08/30 08:45:05 pebinger
 *          Exp $"
 */
public class EncryptedContentInfo extends ASN1Sequence {
    /**
     * The size of the buffer allocated for encrypting.
     */
    public static final int BUFFER_SIZE = 4096;

    /**
     * The OID of PKCS#7 Data
     */
    private static final int[] DATA_OID = { 1, 2, 840, 113549, 1, 7, 1 };

    /**
     * The OID defining the contents of this structure.
     */
    protected ASN1ObjectIdentifier contentType_;

    /**
     * The ContentEncryptionAlgorithmIdentifier
     */
    protected AlgorithmIdentifier cAlg_;

    /**
     * The encrypted content, if present in this structure.
     */
    protected ASN1TaggedType econtent_;

    /**
     * The bulk encryption algorithm.
     */
    protected String bea_;

    /**
     * The bulk encryption key.
     */
    private SecretKey bek_;

    /**
     * The bulk encryption algorithm parameters.
     */
    private AlgorithmParameters params_;

    /**
     * Creates an instance ready for parsing. After decoding of this instance,
     * it must be initialized with one of the <code>init</code> methods,
     * before encryption or decryption operation can commence.
     */
    public EncryptedContentInfo() {
	super(3);

	contentType_ = new ASN1ObjectIdentifier();
	cAlg_ = new AlgorithmIdentifier();
	econtent_ = new ASN1TaggedType(0, new ASN1OctetString(), false, true);

	add(contentType_);
	add(cAlg_);
	add(econtent_);
    }

    /**
     * Initializes an instance with the given secret key, algorithm, and
     * parameters. The content type is set to {@link Data Data}. Instances
     * created with this constructor are ready for encryption and decryption
     * operations by means of the <code>crypt</code> methods.
     * 
     * @param bea
     *                The bulk encryption algorithm name.
     * @param bek
     *                The secret bulk encryption key.
     * @param params
     *                The bulk encryption algorithm parameters.
     */
    public EncryptedContentInfo(String bea, SecretKey bek,
	    AlgorithmParameters params)
	    throws InvalidAlgorithmParameterException {
	if (bea == null || bek == null) {
	    throw new NullPointerException("BEK or BEA is null!");
	}
	contentType_ = new ASN1ObjectIdentifier(DATA_OID);
	cAlg_ = new AlgorithmIdentifier(bea, params);
	econtent_ = new ASN1TaggedType(0, new ASN1OctetString(), false, true);

	add(contentType_);
	add(cAlg_);
	add(econtent_);

	bea_ = bea;
	bek_ = bek;
	params_ = params;
    }

    /**
     * Returns the <code>contentType</code> of this structure. This value is
     * defined only if the structure has been decoded successfully, or the
     * content has been set previously.
     * 
     * @return The OID describing the <code>contentType</code> of this
     *         structure.
     */
    public ASN1ObjectIdentifier getContentType() {
	return contentType_;
    }

    /**
     * This method returns the actual <code>content</code> of this structure.
     * 
     * @return The <code>content</code> or <code>null</code> if no content
     *         is available.
     */
    public byte[] getEncryptedContent() {
	if (econtent_.isOptional()) {
	    return null;
	}
	ASN1OctetString v;

	v = (ASN1OctetString) econtent_.getInnerType();
	return v.getByteArray();
    }

    /**
     * Returns the name of the bulk encryption algorithm name.
     * 
     * @return The algorithm name.
     * @throws IllegalStateException
     *                 if this instance is not yet initialized.
     */
    public String getAlgorithm() {
	if (bea_ == null) {
	    throw new IllegalStateException(
		    "Not initialized or algorithm unresolvable!");
	}
	return bea_;
    }

    /**
     * Returns the algorithm parameters of the bulk encryption algorithm
     * identifier.
     * 
     * @return The algorithm parameters.
     */
    public AlgorithmParameters getParameters() {
	if (params_ == null) {
	    throw new IllegalStateException(
		    "Not initialized or parameters unresolvable!");
	}
	return params_;
    }

    /**
     * Returns the secret bulk encryption key.
     * 
     * @return The BEK or <code>null</code>.
     * @throws IllegalStateException
     *                 if this instance is not yet initialized.
     */
    public SecretKey getSecretKey() {
	if (bek_ == null) {
	    throw new IllegalStateException("Not initialized!");
	}
	return bek_;
    }

    /**
     * Initializes this instance for encryption/decryption with the BEK that is
     * stored in the given {@link RecipientInfo RecipientInfo}. The BEK is
     * decrypted with the given private key and initialized according to the
     * algorithm specified in this instance's
     * contentEncryptionAlgorithmIdentifier.
     * 
     * @param kdk
     *                The private <i>Key Decryption Key</i> required to decrypt
     *                the BEK.
     * @param info
     *                The {@link RecipientInfo RecipientInfo} that holds the
     *                BEK.
     * @throws GeneralSecurityException
     *                 if some cipher related exception is thrown by the
     *                 underlying engines.
     */
    public void init(PrivateKey kdk, RecipientInfo info)
	    throws GeneralSecurityException {
	init();

	bek_ = info.getSecretKey(kdk, bea_);
    }

    /**
     * Initializes this instance for encryption/decryption with the given secret
     * key.
     * 
     * @param key
     *                The secret key that is used to decrypt. The key must match
     *                the algorithm defined in the
     *                contentEncryptionAlgorithmIdentifier.
     * @throws GeneralSecurityException
     *                 if some cipher related exception is thrown by the
     *                 underlying engines.
     */
    public void init(SecretKey key) throws GeneralSecurityException {
	if (key == null) {
	    throw new NullPointerException("Need a SecretKey!");
	}
	init();

	bek_ = key;
    }

    /**
     * Basic initialization.
     */
    protected void init() throws GeneralSecurityException {

	if (params_ == null) {
	    params_ = cAlg_.getParameters();
	}
	if (bea_ == null) {
	    bea_ = cAlg_.getAlgorithmName();
	}
	if (bea_ == null) {
	    throw new NoSuchAlgorithmException("Cannot resolve OID "
		    + cAlg_.getAlgorithmOID());
	}
    }

    /**
     * This method returns <code>true</code> if this instance is ready for
     * encryption/decryption without further initialization.
     * 
     * @return <code>true</code> if it is ready.
     */
    public boolean isReady() {
	if (bek_ == null) {
	    return false;
	}
	return true;
    }

    /**
     * This method initializes and returns a new {@link RecipientInfo
     * RecipientInfo} based on the given certificate. The BEK must already be
     * initialized, otherwise an exception is thrown.
     * 
     * @param cert
     *                the certificate
     * @return the created {@link RecipientInfo}
     * @throws GeneralSecurityException
     *                 if some cipher operation fails.
     * @throws BadNameException
     *                 if the issuer name in the given certificate cannot be
     *                 parsed.
     * @throws IllegalStateException
     *                 if the BEK is not yet initialized.
     */
    public RecipientInfo newRecipient(X509Certificate cert)
	    throws GeneralSecurityException, BadNameException {
	// FIXME Add and adjust saftey check for new Name implementation of
	// Fraunhofer IGD
	// if(!Name.defaultEncoding_)
	// throw new BadNameException("Use the constructor that explicitly sets
	// the Name encoding");
	if (bek_ == null) {
	    throw new IllegalStateException("Not initialized!");
	}
	return new RecipientInfo(cert, bek_);
    }

    /**
     * This method initializes and returns a new {@link RecipientInfo
     * RecipientInfo} based on the given certificate and encoding type. The BEK
     * must already be initialized, otherwise an exception is thrown.
     * 
     * @param cert
     *                the certificate
     * @param encType
     *                the encoding type
     * @return the created {@link RecipientInfo}
     * @throws GeneralSecurityException
     *                 if some cipher operation fails.
     * @throws BadNameException
     *                 if the issuer name in the given certificate cannot be
     *                 parsed.
     * @throws IllegalStateException
     *                 if the BEK is not yet initialized.
     */
    public RecipientInfo newRecipient(X509Certificate cert, int encType)
	    throws GeneralSecurityException, BadNameException {
	if (bek_ == null) {
	    throw new IllegalStateException("Not initialized!");
	}
	return new RecipientInfo(cert, bek_, encType);
    }

    /**
     * Encrypts the given data and inserts it as {@link Data Data} content. The
     * input stream is not closed.
     * 
     * @throws IllegalStateException
     *                 if the DEK is not initialized.
     * @throws GeneralSecurityException
     *                 if something nasty happens while encrypting such as
     *                 algorithms not found, bad paddings et cetera.
     */
    public void setData(InputStream in) throws IOException,
	    GeneralSecurityException {
	ByteArrayOutputStream out;
	byte[] b;

	out = new ByteArrayOutputStream();
	crypt(in, out, Cipher.ENCRYPT_MODE);

	b = out.toByteArray();
	out.close();

	contentType_ = new ASN1ObjectIdentifier(DATA_OID);
	econtent_ = new ASN1TaggedType(0, new ASN1OctetString(b), false, false);

	clear();
	add(contentType_);
	add(cAlg_);
	add(econtent_);
	trimToSize();
    }

    /**
     * This method decrypts and returns the decrypted data contained in this
     * instance or <code>null</code> if there is no contained data.
     * 
     * @throws InconsistentStateException
     *                 in case of an unexpected internal exception. This should
     *                 never happen.
     * @throws IllegalStateException
     *                 if the DEK is not initialized.
     * @throws NoSuchElementException
     *                 if the content type is not {@link Data Data}.
     * @throws GeneralSecurityException
     *                 if a cipher operation fails.
     */
    public byte[] getData() throws GeneralSecurityException,
	    NoSuchElementException {
	byte[] b;
	ByteArrayOutputStream out;

	if (!Arrays.equals(contentType_.getOID(), DATA_OID)) {
	    throw new NoSuchElementException("Content type is not Data!");
	}
	b = getEncryptedContent();

	if (b == null || b.length == 0) {
	    return null;
	}
	try {
	    out = new ByteArrayOutputStream();
	    crypt(b, out, Cipher.DECRYPT_MODE);
	    b = out.toByteArray();
	    out.close();

	    return b;
	} catch (IOException e) {
	    throw new IllegalStateException(e.getMessage());
	}
    }

    /**
     * @param opmode
     *                The operation mode of the cipher.
     * @return A <code>Cipher</code> instance readily initialized for the
     *         given operation mode.
     * @throws GeneralSecurityException
     *                 if something is wrong with the cipher initialization,
     *                 e.g. no bea_ algorithm was found.
     * @throws IllegalStateException
     *                 if this instance is not initialized properly for cipher
     *                 operations. This happens for instance if no secret key
     *                 was set, yet.
     */
    private Cipher createCipher(int opmode) throws GeneralSecurityException {
	Cipher cipher;

	if (bek_ == null) {
	    throw new IllegalStateException("No secret key");
	}
	if (bea_ == null) {
	    throw new IllegalStateException("No cipher algorithm!");
	}
	cipher = Cipher.getInstance(bea_);

	if (params_ == null) {
	    cipher.init(opmode, bek_);
	} else {
	    cipher.init(opmode, bek_, params_);
	}
	return cipher;
    }

    /**
     * Pipes the input to the output while encrypting or decrypting the piped
     * data with the BEK. The output stream is not closed by this method but the
     * input stream is.
     * 
     * @param in
     *                The stream from which data is read.
     * @param out
     *                The stream to which data is written.
     * @param opmode
     *                The operation mode of the cipher, either
     *                <code>Cipher.ENCRYPT_MODE</code> or
     *                <code>Cipher.DECRYPT_MODE</code>.
     * @throws GeneralSecurityException
     *                 if the some cipher operation caused an exception.
     * @throws IllegalStateException
     *                 if the BEK is not initialized.
     * @throws IOException
     *                 if some I/O error is detected.
     */
    public void crypt(InputStream in, OutputStream out, int opmode)
	    throws IOException, GeneralSecurityException {
	Cipher cipher;
	byte[] b;
	int n;

	cipher = createCipher(opmode);
	b = new byte[BUFFER_SIZE];

	while ((n = in.read(b)) > 0) {
	    out.write(cipher.update(b, 0, n));
	}
	out.write(cipher.doFinal());
	out.flush();
	in.close();
    }

    /**
     * Crypts or decrypts the given input bytes and writes the resulting cipher
     * text or clear text tp the given output stream. The output stream is
     * flushed but not closed by this method.
     * 
     * @param in
     *                The byte array from which data is taken.
     * @param out
     *                The stream to which data is written.
     * @param opmode
     *                The operation mode of the cipher, either
     *                <code>Cipher.ENCRYPT_MODE</code> or
     *                <code>Cipher.DECRYPT_MODE</code>.
     * @throws GeneralSecurityException
     *                 if the some cipher operation caused an exception.
     * @throws IllegalStateException
     *                 if the BEK is not initialized.
     * @throws IOException
     *                 if some I/O error is detected.
     */
    public void crypt(byte[] in, OutputStream out, int opmode)
	    throws IOException, GeneralSecurityException {
	Cipher cipher;

	cipher = createCipher(opmode);

	out.write(cipher.doFinal(in));
	out.flush();
    }

    /**
     * Crypts or decrypts the given input bytes and returns the resulting cipher
     * text or clear text.
     * 
     * @param in
     *                The byte array from which data is taken.
     * @param offset
     *                The offset in the byte array at which the data starts.
     * @param length
     *                The number of bytes to operate on starting at the given
     *                offset.
     * @param opmode
     *                The operation mode of the cipher, either
     *                <code>Cipher.ENCRYPT_MODE</code> or
     *                <code>Cipher.DECRYPT_MODE</code>.
     * 
     * @return The resulting cipher text or clear text depending on the
     *         operation mode.
     * 
     * @throws GeneralSecurityException
     *                 if the some cipher operation caused an exception.
     * @throws IllegalStateException
     *                 if the BEK is not initialized.
     */
    public byte[] crypt(byte[] in, int offset, int length, int opmode)
	    throws GeneralSecurityException {
	Cipher cipher;

	cipher = createCipher(opmode);

	return cipher.doFinal(in, offset, length);
    }

    /**
     * Decodes this instance with the given decoder. After decoding, an attempt
     * is made to resolve the algorithm name and parameters.
     * 
     * @param dec
     *                The decoder to use.
     */
    public void decode(Decoder dec) throws IOException, ASN1Exception {
	super.decode(dec);

	try {
	    init();
	} catch (GeneralSecurityException e) {
	    /*
	     * We ignore this exception at this point. It will be thrown again
	     * when this structure is initialized with a key, or algorithm names
	     * or parameters are requested.
	     */
	}
    }

    /**
     * Encrypts the given data and embeds it into this instance. The content
     * type is set to the specified OID.
     * 
     * @param oid
     *                The OID that identifies the content type.
     * @param in
     *                The stream from which the data is read.
     * 
     * @throws IllegalStateException
     *                 if this instance is not properly initialized for
     *                 encryption.
     * @throws GeneralSecurityException
     *                 if something nasty happens while encrypting such as
     *                 algorithms not found, bad paddings et cetera.
     */
    public void setEncryptedContent(ASN1ObjectIdentifier oid, InputStream in)
	    throws IOException, GeneralSecurityException {
	ByteArrayOutputStream out;
	byte[] b;

	if (oid == null || in == null) {
	    throw new NullPointerException("oid or input stream");
	}
	/*
	 * Encrypt the data
	 */
	out = new ByteArrayOutputStream();

	crypt(in, out, Cipher.ENCRYPT_MODE);

	b = out.toByteArray();

	out.close();

	/*
	 * Set the content type
	 */
	contentType_ = oid;

	/*
	 * Embed the content into this structure.
	 */
	econtent_ = new ASN1TaggedType(0, new ASN1OctetString(b), false, false);

	/*
	 * Re-build the structure.
	 */
	clear();
	add(contentType_);
	add(cAlg_);
	add(econtent_);
	trimToSize();
    }

    /**
     * Sets the content type to the given OID. The OID is copied by reference.
     * Modifying it afterwards causes side effects.
     * 
     * @param oid
     *                The OID that identifies the content type.
     */
    public void setContentType(ASN1ObjectIdentifier oid) {
	if (oid == null) {
	    throw new NullPointerException("oid");
	}
	contentType_ = oid;
	set(0, contentType_);
    }

}
