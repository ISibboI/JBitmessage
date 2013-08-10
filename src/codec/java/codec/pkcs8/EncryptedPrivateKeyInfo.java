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
package codec.pkcs8;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import codec.InconsistentStateException;
import codec.asn1.ASN1Exception;
import codec.asn1.ASN1OctetString;
import codec.asn1.ASN1Sequence;
import codec.asn1.DERDecoder;
import codec.x509.AlgorithmIdentifier;

/**
 * This class represents an <code>EncryptedPrivateKeyInfo</code> as defined in
 * <a href="http://www.rsa.com/rsalabs/pubs/PKCS/html/pkcs-8.html"> PKCS#8</a>.
 * The ASN.1 definition of this structure is
 * <p>
 * 
 * <pre>
 * EncryptedPrivateKeyInfo ::= SEQUENCE (
 *   encryptionAlgorithm EncryptionAlgorithmIdentifier,
 *   encryptedData EncryptedData
 * }
 * EncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
 * EncryptedData ::= OCTET STRING 
 * </pre>
 * 
 * @author Volker Roth
 * @version "$Id: EncryptedPrivateKeyInfo.java,v 1.2 2000/12/06 17:47:33 vroth
 *          Exp $"
 */
public class EncryptedPrivateKeyInfo extends ASN1Sequence {

    /**
     * Default PBE encryption algorithm (PBEWithMD5AndDES).
     */
    public static final String DEFAULT_PBE = "PBEWithMD5AndDES";

    /**
     * Default salt length as suggested in the <a
     * href="http://www.rsa.com/rsalabs/pubs/PKCS/html/pkcs-5.html"> PKCS#5
     * Specification</a> is 8.
     */
    public static final int DEFAULT_SALT = 8;

    /**
     * The default iteration count. Used for generating a
     * {@link PBEParameterSpec PBEParameterSpec}
     */
    public static final int DEFAULT_ITERATIONCOUNT = 64;

    /**
     * The result of encrypting the private-key information.
     */
    protected ASN1OctetString encryptedData_;

    /**
     * The name of the algorithm to use when encrypting PrivateKeyInfos or
     * <code>null</code> if the algorithm name is not known or not yet
     * initialized.
     */
    protected AlgorithmIdentifier algorithm_;

    /**
     * The source of randomness used for generating salt values. If no PRNG is
     * set then the default one is used.
     */
    protected SecureRandom random_;

    /**
     * This variable has to be defined as a variable with global scope. It
     * stores the <code>salt</code> and <code>iterationCount</code> used for
     * encoding a private Key. The information is stored as an instance of
     * {@link AlgorithmParameters AlgorithmParameters} used for a later decoding
     * of the key.
     */
    protected PBEParameterSpec pbeParamSpec_;

    /**
     * This method builds the tree of ASN.1 objects used for decoding this
     * structure.
     */
    public EncryptedPrivateKeyInfo() {
	super(2);

	algorithm_ = new AlgorithmIdentifier();
	add(algorithm_);
	encryptedData_ = new ASN1OctetString();
	add(encryptedData_);
    }

    /**
     * Encrypts the given private key information using the given password and
     * stores the resulting encrypted private key info.
     * 
     * @param key
     *                The private key to encrypt.
     * @param passwd
     *                The password to use.
     * @throws GeneralSecurityException
     *                 if there is one of the various exceptions related to
     *                 ciphers being thrown.
     */
    public void setPrivateKey(PrivateKey key, char[] passwd)
	    throws GeneralSecurityException {
	setPrivateKey(key, passwd, DEFAULT_PBE);
    }

    /**
     * This constructor works with a PrivateKey, a password and an algorithm.
     * Any traces of the private key that are created during encryption and
     * encoding are deleted after use unless there is an exception being thrown
     * during encryption.
     * 
     * @param key
     *                The private key to encrypt.
     * @param passwd
     *                The password to use for generating the encryption key.
     * @param algorithm
     *                The name of the PBE algorithm to use for encryption.
     * @throws GeneralSecurityException
     *                 if there is one of the various exceptions related to
     *                 ciphers being thrown.
     */
    public void setPrivateKey(PrivateKey key, char[] passwd, String algorithm)
	    throws GeneralSecurityException {
	if (key == null || passwd == null || algorithm == null)
	    throw new NullPointerException("Some arg is null!");

	AlgorithmParameters params;
	SecretKeyFactory factory;
	PBEParameterSpec pspec;
	PBEKeySpec kspec;
	SecretKey pbekey;
	Cipher cipher;
	byte[] code;
	byte[] salt;
	byte[] buf;

	if (random_ == null)
	    random_ = new SecureRandom();

	salt = new byte[DEFAULT_SALT];
	random_.nextBytes(salt);

	pspec = new PBEParameterSpec(salt, DEFAULT_ITERATIONCOUNT);
	kspec = new PBEKeySpec(passwd);

	factory = SecretKeyFactory.getInstance(algorithm);
	pbekey = factory.generateSecret(kspec);

	cipher = Cipher.getInstance(algorithm);
	cipher.init(Cipher.ENCRYPT_MODE, pbekey, pspec);

	buf = key.getEncoded();
	code = cipher.doFinal(buf);

	Arrays.fill(buf, (byte) 0);

	params = AlgorithmParameters.getInstance(algorithm);
	params.init(pspec);

	clear();

	algorithm_ = new AlgorithmIdentifier(algorithm, params);
	add(algorithm_);
	encryptedData_ = new ASN1OctetString(code);
	add(encryptedData_);
    }

    /**
     * This method decrypts the stored encrypted private key info and extracts
     * the private key from it.
     * 
     * @param password
     *                The password required for decryption.
     * @return The private key.
     * @throws UnrecoverableKeyException
     *                 if the key could not be decrypted or decoded.
     */
    public PrivateKey getPrivateKey(char[] password)
	    throws GeneralSecurityException {
	AlgorithmParameters params;
	AlgorithmIdentifier aid;
	PBEParameterSpec pspec;
	SecretKeyFactory skf;
	PrivateKeyInfo pki;
	KeyFactory kf;
	DERDecoder dec;
	SecretKey secret;
	KeySpec kspec;
	Cipher cipher;
	String name;
	byte[] buf;

	try {
	    name = algorithm_.getAlgorithmOID().toString();
	    params = algorithm_.getParameters();
	    pspec = (PBEParameterSpec) params
		    .getParameterSpec(PBEParameterSpec.class);

	    skf = SecretKeyFactory.getInstance(name);
	    kspec = new PBEKeySpec(password);
	    secret = skf.generateSecret(kspec);

	    cipher = Cipher.getInstance(name);
	    cipher.init(Cipher.DECRYPT_MODE, secret, pspec);

	    buf = cipher.doFinal(encryptedData_.getByteArray());
	    kspec = new PKCS8EncodedKeySpec(buf);

	    pki = new PrivateKeyInfo();
	    dec = new DERDecoder(new ByteArrayInputStream(buf));
	    pki.decode(dec);
	    dec.close();

	    aid = pki.getAlgorithmIdentifier();
	    name = aid.getAlgorithmOID().toString();
	    kf = KeyFactory.getInstance(name);

	    return kf.generatePrivate(kspec);
	} catch (ASN1Exception e) {
	    throw new UnrecoverableKeyException(e.getMessage());
	} catch (IOException e) {
	    throw new InconsistentStateException("Caught IOException!");
	}
    }

}
