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
import java.util.NoSuchElementException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import codec.InconsistentStateException;
import codec.asn1.ASN1Integer;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1RegisteredType;
import codec.asn1.ASN1Sequence;

/**
 * This class represents a <code>EncryptedContentInfo</code> as defined in <a
 * href="http://www.rsa.com/rsalabs/pubs/PKCS/html/pkcs-7.html"> PKCS#7</a>.
 * The ASN.1 definition of this structure is
 * <p>
 * 
 * <pre>
 * EncryptedData ::= SEQUENCE{
 *  version  Version,
 *  encryptedContentInfo EncryptedContentInfo }
 * version is the syntax version number, which shall be 0 for this version.
 * &#064;author Michele Boivin
 * &#064;version &quot;$Id: EncryptedData.java,v 1.4 2005/03/22 13:46:25 flautens Exp $&quot;
 * 
 */
public class EncryptedData extends ASN1Sequence implements ASN1RegisteredType {
    /**
     * The OID of this structure. PKCS#7 Data
     */
    private static final int[] OID_ = { 1, 2, 840, 113549, 1, 7, 6 };

    /**
     * the verson of this syntax
     */
    protected static ASN1Integer version_;

    /**
     * the actual content of this structure.
     */
    protected EncryptedContentInfo info_;

    /**
     * Creates an instance ready for decoding.
     */
    public EncryptedData() {
	super(2);

	version_ = new ASN1Integer(0);
	info_ = new EncryptedContentInfo();

	add(version_);
	add(info_);
    }

    /**
     * Creates an instance and initializes it with the given key, algorithm, and
     * parameters. The parameters can be <code>null</code> if none should be
     * used.
     * 
     * @param bea
     *                The bulk encryption algorithm name.
     * @param bek
     *                The secret key to use.
     * @param params
     *                The algorithm parameters or <code>null
     *   </code> if none
     *                are present.
     * @throws InvalidAlgorithmParameterException
     *                 if there is a problem with the parameters.
     * @throws NullPointerException
     *                 if <code>bea</code> or <code>bek</code> are
     *                 <code>null</code>.
     */
    public EncryptedData(String bea, SecretKey bek, AlgorithmParameters params)
	    throws InvalidAlgorithmParameterException {
	super(2);

	if (bea == null || bek == null) {
	    throw new NullPointerException("BEA or BEK is null!");
	}
	version_ = new ASN1Integer(0);
	info_ = new EncryptedContentInfo(bea, bek, params);

	add(version_);
	add(info_);
    }

    /**
     * Initializes the underlying {@link EncryptedContentInfo
     * EncryptedContentInfo} with the given bulk encryption key.
     * 
     * @param key
     *                The BEK to use for encrypting or decrypting.
     * @throws GeneralSecurityException
     *                 if a problem with some of the involved provider engines
     *                 is detected.
     */
    public void init(SecretKey key) throws GeneralSecurityException {
	info_.init(key);
    }

    /**
     * Returns The OID of this structure. PKCS#7 Data
     * 
     * @return OID of this structure.
     */
    public ASN1ObjectIdentifier getOID() {
	return new ASN1ObjectIdentifier(OID_);
    }

    /**
     * This method returns the actual <code>content</code> of this structure.
     * 
     * @return The <code>content</code> or <code>null</code> if no content
     *         is available.
     */
    public byte[] getEncryptedContent() {
	return info_.getEncryptedContent();
    }

    /**
     * Returns the name of the bulk encryption algorithm name.
     * 
     * @return The algorithm name.
     * @throws IllegalStateException
     *                 if this instance is not yet initialized.
     */
    public String getAlgorithm() {
	return info_.getAlgorithm();
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
     * Returns the actual content of this structure.
     * 
     * @return The actual content
     */
    public EncryptedContentInfo getContentInfo() {
	return info_;
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
     * @param in
     *                The data to insert.
     * @throws IllegalStateException
     *                 if the DEK is not initialized.
     * @throws GeneralSecurityException
     *                 if something nasty happens while encrypting such as
     *                 algorithms not found, bad paddings et cetera.
     * @throws IOException
     *                 if stream operation fails.
     */
    public void setData(InputStream in) throws IOException,
	    GeneralSecurityException {
	info_.setData(in);
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
     * @return The decrypted data contained in this instance or null if there is
     *         no contained data.
     */
    public byte[] getData() throws GeneralSecurityException,
	    NoSuchElementException {
	return info_.getData();
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
     * @throws IOException
     *                 if stream operation fails.
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
     * @throws IOException
     *                 if stream operation fails.
     */
    public void encryptBulkData(InputStream in, OutputStream out)
	    throws IOException, GeneralSecurityException {
	info_.crypt(in, out, Cipher.ENCRYPT_MODE);
    }

}
