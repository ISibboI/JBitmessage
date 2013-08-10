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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import codec.asn1.ASN1Integer;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1RegisteredType;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1SetOf;
import codec.x501.BadNameException;

/**
 * This class represents the PKCS#7 EnvelopedData type, which is defined as
 * follows:
 * 
 * <pre>
 * EnvelopedData ::= SEQUENCE {
 *   version Version,
 *   recipientInfos RecipientInfos,
 *   encryptedContentInfo EncryptedContentInfo
 * }
 * RecipientInfos ::= SET OF RecipientInfo
 * </pre>
 * 
 * See class {@link RecipientInfo RecipientInfo} for a description of the
 * RecipientInfo structure.
 * 
 * @author Volker Roth
 * @version "$Id: EnvelopedData.java,v 1.6 2004/08/12 12:16:19 pebinger Exp $"
 */
public class EnvelopedData extends ASN1Sequence implements ASN1RegisteredType {
    /**
     * The size of the buffer allocated for reading and verifying data in case
     * this is a detached signature file.
     */
    public static final int BUFFER_SIZE = 1024;

    /**
     * The OID of this structure. PKCS#7 EnvelopedData.
     */
    private static final int[] THIS_OID = { 1, 2, 840, 113549, 1, 7, 3 };

    /**
     * The version of this structure.
     */
    protected ASN1Integer version_;

    /**
     * The RecipientInfos.
     */
    protected ASN1SetOf recipients_;

    /**
     * The {@link EncryptedContentInfo EncryptedContentInfo}.
     */
    protected EncryptedContentInfo info_;

    /**
     * The {@link ContentInfo ContentInfo}.
     */
    protected ContentInfo content_;

    /**
     * This method calls builds the tree of ASN.1 objects used for decoding this
     * structure.
     */
    public EnvelopedData() {
	super(3);

	version_ = new ASN1Integer(0);
	recipients_ = new ASN1SetOf(RecipientInfo.class);
	info_ = new EncryptedContentInfo();

	add(version_); // version
	add(recipients_);
	add(info_);
    }

    /**
     * Creates an instance that is initialized with the given secret key and
     * algorithm parameters. If this constructor is used then this instance need
     * not be initialized anymore with the {@link #init init} method for adding
     * recipients.
     * 
     * @param bek
     *                The secret key to use for bulk encryption.
     * @param bea
     *                The name of the bulk encryption algorithm.
     * @param params
     *                The AlgorithmParameters of the bulk encryption algorithm.
     * @throws InvalidAlgorithmParameterException
     *                 just what is says...
     */
    public EnvelopedData(SecretKey bek, String bea, AlgorithmParameters params)
	    throws InvalidAlgorithmParameterException {
	super(3);

	version_ = new ASN1Integer(0);
	recipients_ = new ASN1SetOf(RecipientInfo.class);
	info_ = new EncryptedContentInfo(bea, bek, params);

	add(version_); // version
	add(recipients_);
	add(info_);
    }

    /**
     * Returns the OID of this structure.
     * 
     * @return The OID.
     */
    public ASN1ObjectIdentifier getOID() {
	return new ASN1ObjectIdentifier(THIS_OID);
    }

    /**
     * Retrieves and returns the content type of the content stored in the
     * <code>encryptedContentInfo</code> of this structure. This value is
     * meaningful only if this instance was decoded or initialized properly.
     */
    public ASN1ObjectIdentifier getContentType() {
	return info_.getContentType();
    }

    /**
     * This method returns the <code>EncryptedContentInfo</code> embedded in
     * this instance. This method is hardly ever used. Its primary purpose is to
     * allow customized decryption of bulk encryption keys e.g., via SmartCards.
     * This would work as follows: The application
     * <ul>
     * 
     * <li> retrieves a matching <code>RecipientInfo</code> from this instance
     * and extracts the encrypted bulk encryption key and the (asymmetric) key
     * encryption algorithm identifier (with parameters and algorithm
     * identifier).
     * 
     * <li> retrieves the <code>EncryptedContentInfo</code> and from that the
     * bulk encryption algorithm and the bulk encryption algorithm parameters.
     * 
     * <li> decrypts and generates the secret bulk encryption key by customized
     * means (e.g., via SmartCard).
     * 
     * <li> initializes the <code>EncryptedContentInfo</code> directly with
     * the freshly decrypted bulk encryption key.
     * 
     * <li> decrypts the bulk data either via this class or directly via the
     * embedded <code>EncryptedContentInfo</code> instance.
     * 
     * </ul>
     * 
     * @return The <code>EncryptedContentInfo</code>
     */
    public EncryptedContentInfo getEncryptedContentInfo() {
	return info_;
    }

    /**
     * This method returns an unmodifiable list view on the
     * {@link RecipientInfo RecipientInfos} of this structure.
     * 
     * @return The list of recipient infos.
     */
    public List getRecipientInfos() {
	return Collections.unmodifiableList(recipients_);
    }

    /**
     * This method checks if the given certificate is listed as a recipient by
     * comparing the issuer and serial number of the given certificate with
     * those listed in the {@link RecipientInfo recipient infos} of this
     * instance.
     * 
     * @param cert
     *                The certificate that identifies the recipient.
     * @return <code>true</code> if a recipient who matches the given
     *         certificate is included in this structure.
     */
    public boolean hasRecipient(X509Certificate cert) {
	if (getRecipientInfo(cert) == null) {
	    return false;
	}
	return true;
    }

    /**
     * This method retrieves the {@link RecipientInfo RecipientInfo} macthing
     * the given certificate or <code>null</code> if there is no such
     * recipient.
     * 
     * @param cert
     *                The certificate that identifies the recipient.
     * @return The RecipientInfo of the recipient or <code>null
     *   </code> if no
     *         matching recipient was found.
     */
    public RecipientInfo getRecipientInfo(X509Certificate cert) {
	RecipientInfo ri;
	Iterator i;

	for (i = recipients_.iterator(); i.hasNext();) {
	    ri = (RecipientInfo) i.next();

	    if (ri.getIssuer().equals(cert.getIssuerDN())
		    && ri.getSerialNumber().equals(cert.getSerialNumber())) {
		return ri;
	    }
	}
	return null;
    }

    /**
     * This method adds a recipient to the list of recipients. Please note that
     * this works only if the underlying
     * {@link EncryptedContentInfo EncryptedContentInfo} is initialized
     * properly. This is done by either of two means:
     * <ul>
     * <li> creating an instance of this class with the non-default constructor
     * that takes as arguments a secret key and algorithm parameters, or
     * <li> by calling {@link #init init} with a certificate that is listed as
     * recipient and appropriate private key.
     * </ul>
     * This ensures that the bulk encryption key is available. This key is then
     * encrypted for the recipient specified in the given certificate (by
     * encrypting with the public key enclosed in it) and an appropriate
     * {@link RecipientInfo RecipientInfo} instance is created and added to the
     * list of recipient infos in this instance.
     * 
     * @param cert
     *                The certificate of the recipient.
     * @throws GeneralSecurityException
     *                 if some cipher operation fails. The reason can
     *                 bedetermined from the actual subclass that is thrown.
     * @throws BadNameException
     *                 if the issuer name in the certificate cannot be parsed.
     */
    public void addRecipient(X509Certificate cert)
	    throws GeneralSecurityException, BadNameException {
	if (!hasRecipient(cert)) {
	    recipients_.add(info_.newRecipient(cert));
	}
    }

    /**
     * same as above but with an explicit encodingType
     * 
     * @param cert
     * @param encType
     * @throws GeneralSecurityException
     * @throws BadNameException
     */
    public void addRecipient(X509Certificate cert, int encType)
	    throws GeneralSecurityException, BadNameException {
	if (!hasRecipient(cert)) {
	    recipients_.add(info_.newRecipient(cert, encType));
	}
    }

    /**
     * Initializes this instance for encryption/decryption. The given
     * certificate must be registered as recipient and the private key must
     * match the certificate. This method actually looks for a
     * {@link RecipientInfo RecipientInfo} matching the given certificate and
     * calls {@link EncryptedContentInfo#init(PrivateKey, RecipientInfo) init}
     * of the {@link EncryptedContentInfo EncryptedContentInfo} contained in
     * this structure.
     * <p>
     * 
     * This method need to be called only if this instance was not initialized
     * with a secret key for bulk encryption, but was initialized through
     * parsing it from a DER stream. In other words, this method is probably
     * used only when reading EnvelopedData sent by someone else but hardly ever
     * if it is generated.
     * <p>
     * 
     * Please note that, once this instance is properly initialized, additional
     * recipients might be added to it unless this structure is protected by
     * integrity measures (such as wrapping it in a
     * {@link SignedData SignedData} structure.
     * 
     * @param kdk
     *                The private <i>Key Decryption Key</i> required to decrypt
     *                the DEK.
     * @param cert
     *                The certificate matching the private key.
     * 
     * @throws GeneralSecurityException
     *                 if some cipher operation fails.
     * @throws NoSuchElementException
     *                 if no matching {@link RecipientInfo RecipientInfo} is
     *                 found in this instance.
     */
    public void init(X509Certificate cert, PrivateKey kdk)
	    throws GeneralSecurityException, NoSuchElementException {
	RecipientInfo ri;

	ri = getRecipientInfo(cert);

	if (ri == null) {
	    throw new NoSuchElementException("No such recipient exists!");
	}
	info_.init(kdk, ri);
    }

    /**
     * This method returns <code>true</code> if this instance is ready for
     * encryption/decryption without further initialization.
     * 
     * @return <code>true</code> if it is ready.
     */
    public boolean isReady() {
	return info_.isReady();
    }

    /**
     * Encrypts the given data and inserts it as {@link Data Data} content.
     * 
     * @throws IllegalStateException
     *                 if the DEK is not initialized.
     * @throws GeneralSecurityException
     *                 if something nasty happens while encrypting such as
     *                 algorithms not found, bad paddings et cetera.
     */
    public void setData(InputStream in) throws GeneralSecurityException,
	    IOException {
	info_.setData(in);
    }

    /**
     * This method decrypts and returns the decrypted data contained in this
     * instance or <code>null</code> if there is no contained data.
     * 
     * @throws IllegalStateException
     *                 if the DEK is not initialized.
     * @throws NoSuchElementException
     *                 if the content type is not {@link Data Data}.
     * @throws GeneralSecurityException
     *                 if a cipher operation fails.
     */
    public byte[] getData() throws GeneralSecurityException,
	    NoSuchElementException {
	return info_.getData();
    }

    /**
     * This method returns the secret bulk encryption key if the underlying
     * EncryptedContentInfo structure is already initialized properly (by
     * calling one of this object's {@link #init init} methods). If the key is
     * not available (yet) then <code>null</code> is returned.
     * 
     * @return The BEK or <code>null</code>.
     * @throws IllegalStateException
     *                 if this instance is not yet initialized.
     */
    public SecretKey getSecretKey() {
	return info_.getSecretKey();
    }

    /**
     * This method reads encrypted bulk data from the input stream, decrypts and
     * writes the decrypted data to the given output stream. This instance must
     * be properly initialized for this operation to work.
     * 
     * @param in
     *                The input stream from which the data is read.
     * @param out
     *                The output stream to which the data is written.
     */
    public void decryptBulkData(InputStream in, OutputStream out)
	    throws IOException, GeneralSecurityException {
	info_.crypt(in, out, Cipher.DECRYPT_MODE);
    }

    /**
     * This method reads plaintext bulk data from the input stream, encrypts it
     * and writes the encrypted data to the given output stream. This instance
     * must be properly initialized for this operation to work.
     * 
     * @param in
     *                The input stream from which the data is read.
     * @param out
     *                The output stream to which the data is written.
     */
    public void encryptBulkData(InputStream in, OutputStream out)
	    throws IOException, GeneralSecurityException {
	info_.crypt(in, out, Cipher.ENCRYPT_MODE);
    }

}
