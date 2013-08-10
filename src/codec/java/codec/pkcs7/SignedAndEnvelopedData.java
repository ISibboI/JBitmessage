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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import codec.asn1.ASN1Integer;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1Opaque;
import codec.asn1.ASN1RegisteredType;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1Set;
import codec.asn1.ASN1SetOf;
import codec.asn1.ASN1TaggedType;
import codec.asn1.ASN1Type;
import codec.util.CertificateSource;
import codec.x501.BadNameException;
import codec.x509.AlgorithmIdentifier;

/**
 * The definition of this structure is: <blockquote>
 * 
 * <pre>
 * SignedAndEnvelopedData ::= SEQUENCE {
 *   version Version,
 *   recipientInfos RecipientInfos,
 *   digestAlgorithms DigestAlgorithmIdentifiers,
 *   encryptedContentInfo EncryptedContentInfo,
 *   certificates
 *     [0] IMPLICIT ExtendedCertificatesAndCertificates OPTIONAL,
 *   crls
 *     [1] IMPLICIT CertificateRevocationLists OPTIONAL,
 *   signerInfos SignerInfos
 * }
 * DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
 * SignerInfos ::= SET OF SignerInfo
 * </pre>
 * 
 * </blockquote>
 * 
 * Please note that <code>SignerInfo</code> structures only store the issuer
 * and serial number of the signing certificate but not the certificate itself.
 * Neither are certificates added automatically by this class when signing is
 * done. If a certificate shall be included with an instance of this class then
 * it must be added explicitly by calling <code>addCertificate(..)</code>.
 * <p>
 * 
 * The encryption and decryption methods of this class do not work like
 * <code>update(...)</code> of a <code>Cipher</code> class but encrypt and
 * decrypt data with a freshly initialized cipher instance.
 * 
 * @author Volker Roth
 * @author Markus Tak
 * @version "$Id: SignedAndEnvelopedData.java,v 1.6 2002/08/28 21:40:35 jpeters
 *          Exp $"
 */
public class SignedAndEnvelopedData extends ASN1Sequence implements
	ASN1RegisteredType, CertificateSource, Signable, Serializable {
    /**
     * The OID of this structure. PKCS#7 SignedAndEnvelopedData.
     */
    private static final int[] THIS_OID = { 1, 2, 840, 113549, 1, 7, 4 };

    /**
     * The PKCS#7 Data OID.
     */
    private static final int[] DATA_OID = { 1, 2, 840, 113549, 1, 7, 1 };

    /**
     * The DigestAlgorithmIdentifiers.
     */
    protected ASN1Set digestID_;

    /**
     * The X.509 certificates.
     */
    protected Certificates certs_;

    /**
     * The {@link SignerInfo SignerInfos}.
     */
    protected ASN1SetOf sInfos_;

    /**
     * The revocation lists.
     */
    protected ASN1Set crls_;

    /**
     * The RecipientInfos.
     */
    protected ASN1SetOf recipients_;

    /**
     * The {@link EncryptedContentInfo EncryptedContentInfo}.
     */
    protected EncryptedContentInfo info_;

    /**
     * The cache encoded X.509 certificates. This cache is filled with opaque
     * versions on encoding this instance.
     */
    protected ASN1Set cache_;

    /**
     * The certificate factory that is used for decoding certificates.
     */
    protected CertificateFactory factory_;

    /**
     * Creates an instance ready for decoding.
     */
    public SignedAndEnvelopedData() {
	super(6);

	add(new ASN1Integer(1)); // version

	recipients_ = new ASN1SetOf(RecipientInfo.class);
	add(recipients_);

	digestID_ = new ASN1SetOf(AlgorithmIdentifier.class);
	add(digestID_);

	info_ = new EncryptedContentInfo();
	add(info_);

	certs_ = new Certificates();
	add(new ASN1TaggedType(0, certs_, false, true));

	crls_ = new ASN1SetOf(ASN1Opaque.class);
	add(new ASN1TaggedType(1, crls_, false, true));

	sInfos_ = new ASN1SetOf(SignerInfo.class);
	add(sInfos_);
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
    public SignedAndEnvelopedData(SecretKey bek, String bea,
	    AlgorithmParameters params)
	    throws InvalidAlgorithmParameterException {
	super(6);

	add(new ASN1Integer(1)); // version

	recipients_ = new ASN1SetOf(RecipientInfo.class);
	add(recipients_);

	digestID_ = new ASN1SetOf(AlgorithmIdentifier.class);
	add(digestID_);

	info_ = new EncryptedContentInfo(bea, bek, params);
	add(info_);

	certs_ = new Certificates();
	add(new ASN1TaggedType(0, certs_, false, true));

	crls_ = new ASN1SetOf(ASN1Opaque.class);
	add(new ASN1TaggedType(1, crls_, false, true));

	sInfos_ = new ASN1SetOf(SignerInfo.class);
	add(sInfos_);
    }

    /**
     * Adds the given certificate to this structure if none with the same issuer
     * and serial number already exists.
     * 
     * @param cert
     *                The certificate to add.
     */
    public void addCertificate(X509Certificate cert) {
	if (certs_.addCertificate(cert)) {
	    ((ASN1Type) get(4)).setOptional(false);
	}
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
     * Adds the given {@link SignerInfo SignerInfo} to this instance. This
     * method should be used rarely. In general, the signing methods take care
     * of adding <code>SignerInfo
     * </code> instances. Explicit adding of a
     * <code>SignerInfo
     * </code> is provided only in those cases where fine
     * control of the creation of signatures is required.
     * 
     * @param info
     *                The <code>SignerInfo</code> to add.
     * @throws NullPointerException
     *                 if the <code>info</code> is <code>null</code>.
     */
    public void addSignerInfo(SignerInfo info) {
	AlgorithmIdentifier idn;
	AlgorithmIdentifier idv;
	Iterator i;

	if (info == null) {
	    throw new NullPointerException("Need a SignerInfo!");
	}
	sInfos_.add(info);

	/*
	 * We also have to add the DigestAlgorithmIdentifier of the SignerInfo
	 * to the list of digest algs if it is not yet in the list.
	 */
	idn = info.getDigestAlgorithmIdentifier();

	for (i = digestID_.iterator(); i.hasNext();) {
	    idv = (AlgorithmIdentifier) i.next();

	    if (idn.equals(idv)) {
		return;
	    }
	}
	digestID_.add(idn);
    }

    public Iterator certificates(Principal subject) {
	return certs_.certificates(subject);
    }

    public Iterator certificates(Principal subject, int keyUsage) {
	return certs_.certificates(subject, keyUsage);
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

    public byte[] decryptBulkData(byte[] b) throws GeneralSecurityException {
	return info_.crypt(b, 0, b.length, Cipher.DECRYPT_MODE);
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

    public byte[] encryptBulkData(byte[] b) throws GeneralSecurityException {
	return info_.crypt(b, 0, b.length, Cipher.ENCRYPT_MODE);
    }

    public X509Certificate getCertificate(Principal issuer, BigInteger serial) {
	return certs_.getCertificate(issuer, serial);
    }

    /**
     * This method returns the certificates stored in this structure. Each
     * certificate can be casted to a <code>X509Certificate</code>.
     * 
     * @return An unmodifiable list view of the certificates.
     */
    public List getCertificates() {
	return Collections.unmodifiableList(certs_);
    }

    /**
     * This method retrieves the content of this structure, consisting of the
     * ASN.1 type embedded in the ContentInfo structure. Beware, the content
     * type might be faked by adversaries, if it is not of type
     * {@link Data Data}. If it is not data then the authenticated content type
     * must be given as an authenticated attribute in all the {@link SignerInfo
     * SignerInfo} structures.
     * 
     * @return The contents octets.
     */
    public ASN1Type getContent() throws GeneralSecurityException {
	return new Data(getData());
    }

    /**
     * Returns the content type of the content embedded in this structure. The
     * returned OID is a copy, no side effects are caused by modifying it.
     * 
     * @return The content type of this structure's payload.
     */
    public ASN1ObjectIdentifier getContentType() {
	return (ASN1ObjectIdentifier) info_.getContentType().clone();
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
     * Returns the OID of this structure. The returned OID is a copy, no side
     * effects are caused by modifying it.
     * 
     * @return The OID.
     */
    public ASN1ObjectIdentifier getOID() {
	return new ASN1ObjectIdentifier(THIS_OID);
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
     * This method returns an unmodifiable list view on the
     * {@link RecipientInfo RecipientInfos} of this structure.
     * 
     * @return The list of recipient infos.
     */
    public List getRecipientInfos() {
	return Collections.unmodifiableList(recipients_);
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
     * Returns the <code>SignerInfo</code> that matches the given certificate.
     * 
     * @param cert
     *                The certificate matching the <code>SignerInfo
     *   </code> to
     *                be retrieved.
     * @return The <code>SignerInfo</code> or <code>null</code> if no
     *         matching one is found.
     */
    public SignerInfo getSignerInfo(X509Certificate cert) {
	SignerInfo info;
	Iterator i;

	for (i = getSignerInfos().iterator(); i.hasNext();) {
	    info = (SignerInfo) i.next();

	    if (!info.getIssuerDN().equals(cert.getIssuerDN())) {
		continue;
	    }
	    if (info.getSerialNumber().equals(cert.getSerialNumber())) {
		return info;
	    }
	}
	return null;
    }

    /**
     * This method returns the {@link SignerInfo SignerInfos} of the signers of
     * this structure.
     * 
     * @return The unmodifiable view of the list of SignerInfos.
     */
    public List getSignerInfos() {
	return Collections.unmodifiableList(sInfos_);
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
	return (getRecipientInfo(cert) != null);
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
     * Sets the certificate factory to use for decoding certificates.
     * 
     * @param factory
     *                The certificate factory or <code>null
     *   </code> if the
     *                default <code>X.509</code> factory shall be used.
     */
    public void setCertificateFactory(CertificateFactory factory) {
	certs_.setCertificateFactory(factory);
    }

    /**
     * Sets the content type to the given OID. The content itself is set to
     * <code>null</code>. This method should be called if the content to be
     * signed is external (not inserted into this structure).
     * <p>
     * 
     * If this structure is signed with the {@link Signer Signer} then the
     * {@link SignerInfo SignerInfo} that is passed to it must have either:
     * <ul>
     * <li> no authenticated content type attribute, or
     * <li> the authenticated content type attribute must match <code>oid</code>.
     * </ul>
     * In the first case, a new authenticated content type attribute with
     * <code>oid</code> as its value will be added to the
     * <code>SignerInfo</code> automatically (if the content type is not
     * {@link Data Data} or at least one other authenticated attribute is
     * already in that <code>SignerInfo</code>.
     * 
     * @param oid
     *                The OID that identifies the content type of the signed
     *                data.
     * @throws NullPointerException
     *                 if <code>oid</code> is <code>null</code>.
     */
    public void setContentType(ASN1ObjectIdentifier oid) {
	if (oid == null) {
	    throw new NullPointerException("OID");
	}
	info_.setContentType(oid);
    }

    /**
     * This method wraps the given bytes into a {@link Data Data} type and sets
     * it as the content.
     * <p>
     * 
     * Please note that the signing process implemented in this class does not
     * care about the content. Setting a content before signing does <b>not</b>
     * sign the content. The data to be signed must always be passed to one of
     * the <code>
     * update</code> methods.
     * 
     * @param b
     *                The opaque contents to embed in this structure.
     * @throws IllegalStateException
     *                 if the DEK is not initialized.
     * @throws GeneralSecurityException
     *                 if something nasty happens while encrypting such as
     *                 algorithms not found, bad paddings et cetera.
     */
    public void setData(byte[] b) throws IOException, GeneralSecurityException {
	ByteArrayInputStream bis;

	bis = new ByteArrayInputStream(b);
	try {
	    info_.setData(bis);
	} finally {
	    bis.close();
	}
    }

    /**
     * Encrypts the given data and inserts it as {@link Data Data} content. The
     * stream is not closed.
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
     * Sets the content type to {@link Data Data} and clears the actual content.
     * Call this method when external data is signed, and no particular content
     * type shall be used. This method calls <code>
     * setContentType(new ASN1ObjectIdentifier(DATA_OID))
     * </code>.
     */
    public void setDataContentType() {
	setContentType(new ASN1ObjectIdentifier(DATA_OID));
    }

    /**
     * Returns a string representation of this object.
     * 
     * @return The string representation.
     */
    public String toString() {
	return "-- PKCS#7 SignedAndEnvelopedData --\n" + super.toString();
    }
}
