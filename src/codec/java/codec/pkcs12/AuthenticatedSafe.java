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
package codec.pkcs12;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.NoSuchElementException;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import codec.asn1.ASN1Exception;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1SequenceOf;
import codec.asn1.BERDecoder;
import codec.asn1.DEREncoder;
import codec.pkcs7.ContentInfo;
import codec.pkcs7.Data;
import codec.pkcs7.EncryptedData;
import codec.pkcs7.EnvelopedData;
import codec.x501.BadNameException;

/**
 * This class represents an <code>AuthenticatedSafe</code> as defined in <a
 * href="http://www.rsasecurity.com/rsalabs/pkcs/pkcs-12/index.html"> PKCS#12</a>.
 * The ASN.1 definition of this structure is
 * <p>
 * 
 * <pre>
 *  AuthenticatedSafe ::= SEQUENCE OF ContentInfo
 *   --Data if unencrypted
 *   --Encrypted data if password-encrypted
 *   --Enveloped data if public-key-encrypted
 * </pre>
 * 
 * <p>
 * <code>PFX</code> The AuthenicatedSafe PDUs hold the data to be transmitted.
 * 
 * 
 * @author Michele Boivin
 * @version "$Id: AuthenticatedSafe.java,v 1.4 2005/03/22 13:57:42 flautens Exp $"
 */
public class AuthenticatedSafe extends ASN1SequenceOf implements
	java.io.Serializable {
    /**
     * The OID of this structure.
     */
    private static final int[] OID_ = { 1, 2, 840, 113549, 1, 12, 10, 1, 6 };

    /**
     * identifies no protection mode
     */
    public static final int NO_PROTECTION = 0;

    /**
     * identifies password protection mode
     */
    public static final int PASSWORD_PROTECTION = 1;

    /**
     * identifies public-key-protection mode
     */
    public static final int PUBLIC_KEY_PROTECTION = 2;

    /**
     * the default constructor.
     */
    public AuthenticatedSafe() {
	super(ContentInfo.class);
    }

    /**
     * Constructs a SafeContents from a SafeBag. WARNING! This SafeContents is
     * not protected.
     * 
     * @param safe
     *                The SafeContents to put in the AuthenticatedSafe.
     */
    public AuthenticatedSafe(SafeContents safe) throws IOException,
	    ASN1Exception {
	super(ContentInfo.class);
	addSafeContents(safe);
    }

    /**
     * Constructs an AuthenticatedSafe and places a SafeContents in it protected
     * by a password.
     * 
     * @param safe
     *                The SafeContents to put in the AuthenticatedSafe
     * @param passwd
     *                The password used to protect the contents of the
     *                SafeContents.
     * @param algorithm
     *                the PBE algorithm to be used
     */
    public AuthenticatedSafe(SafeContents safe, char[] passwd, String algorithm)
	    throws IOException, ASN1Exception, GeneralSecurityException {
	super(ContentInfo.class);
	addSafeContents(safe, passwd, algorithm);
    }

    /**
     * Creates an authenticated safe and places a SafeContents in
     * public-key-encrypted mode inside. The SafeContents will be saved as type
     * {@link codec.pkcs7.EnvelopedData} and therefore requires a secret key and
     * a certificate.
     * 
     * @param safe
     *                The SafeContents to put in the AuthenticatedSafe
     * @param key
     *                The secret key for the symmetric encryption
     * @param algorithm
     *                the symmetric encryption algorithm
     * @param params
     *                algorithm parameters for the symmetric encryption
     *                algorithm
     * @param cert
     *                The certificate chain for the intended recipients of the
     *                SafeContents
     */
    public AuthenticatedSafe(SafeContents safe, SecretKey key,
	    String algorithm, AlgorithmParameters params,
	    java.security.cert.X509Certificate[] cert) throws IOException,
	    ASN1Exception, BadNameException, GeneralSecurityException {
	super(ContentInfo.class);
	addSafeContents(safe, key, algorithm, params, cert);
    }

    /**
     * Adds a SafeContents to the AuthenticatedSafe. WARNING! This SafeContents
     * is not protected.
     * 
     * @param safe
     *                the SafeContents to be added to the AuthenticatedSafe
     */
    public void addSafeContents(SafeContents safe) throws IOException,
	    ASN1Exception {
	ContentInfo cinfo = makeData(safe);
	add(cinfo);
    }

    /**
     * adds a safeContents to the AuthenticatedSafe and protects it with a
     * password.
     * 
     * @param safe
     *                The SafeContents to put in the AuthenticatedSafe
     * @param passwd
     *                The password used to protect the contents of the
     *                SafeContents.
     * @param algorithm
     *                the PBE algorithm to be used
     */
    public void addSafeContents(SafeContents safe, char[] passwd,
	    String algorithm) throws IOException, ASN1Exception,
	    GeneralSecurityException {
	ContentInfo cinfo = makeEncryptedData(safe, passwd, algorithm);
	add(cinfo);
    }

    /**
     * Adds a SafeContents to the AuthenticatedSafe. The SafeContents will be
     * saved as type {@link codec.pkcs7.EnvelopedData} and therefore requires a
     * secret key and a certificate.
     * 
     * @param safe
     *                The SafeContents to put in the AuthenticatedSafe
     * @param key
     *                The secret key for the symmetric encryption
     * @param algorithm
     *                the symmetric encryption algorithm
     * @param params
     *                algorithm parameters for the symmetric encryption
     *                algorithm
     * @param cert
     *                The certificate chain for the intended recipients of the
     *                SafeContents
     */
    public void addSafeContents(SafeContents safe, SecretKey key,
	    String algorithm, AlgorithmParameters params,
	    java.security.cert.X509Certificate[] cert) throws IOException,
	    ASN1Exception, BadNameException, GeneralSecurityException {
	ContentInfo cinfo = makeEnvelopedData(safe, key, algorithm, params,
		cert);
	add(cinfo);
    }

    /**
     * A SafeContents can be put recursively into a SafeBag.
     * 
     * @return the OID defining this structure as a SafeContents bag.
     */
    public ASN1ObjectIdentifier getOID() {
	return new ASN1ObjectIdentifier(OID_);
    }

    /**
     * Returns the protection mode of each SafeContents in the AuthenticatedSafe
     * 
     * @return the protection mode of each SafeContents
     */
    public int[] getProtectionMode() {
	int[] proMode;
	proMode = new int[this.size()];
	for (int i = 0; i < this.size(); i++) {
	    ContentInfo cinfo = (ContentInfo) this.get(i);
	    if (cinfo.getContent() instanceof Data) {
		proMode[i] = NO_PROTECTION;
	    } else if (cinfo.getContent() instanceof EncryptedData) {
		proMode[i] = PASSWORD_PROTECTION;
	    } else if (cinfo.getContent() instanceof EnvelopedData) {
		proMode[i] = PUBLIC_KEY_PROTECTION;
	    } else {
		throw new IllegalStateException("Illegal protection mode: "
			+ proMode[i]);
	    }
	}
	return proMode;
    }

    /**
     * returns the contents of the SafeBag in the AuthenticatedSafe at position
     * i, if the SafeBag is not protected.
     * 
     * @param i
     *                The integer specifying the position.
     * @return The SafeBag at position i.
     */
    public SafeContents getSafeContents(int i) throws IOException,
	    ASN1Exception {
	byte[] encodedData;
	ByteArrayInputStream bais;
	ContentInfo cinfo = (ContentInfo) this.get(i);
	if (cinfo.getContent() instanceof Data) {
	    encodedData = ((Data) cinfo.getContent()).getByteArray();
	} else {
	    System.out
		    .println("This bag is either password or public-key protected.");
	    return null;
	}
	bais = new ByteArrayInputStream(encodedData);
	SafeContents safe = new SafeContents();
	BERDecoder decoder = new BERDecoder(bais);
	safe.decode(decoder);
	bais.close();
	return safe;
    }

    /**
     * returns the contents of the SafeBag in the AuthenticatedSafe at position
     * i, if the SafeBag is password-protected.
     * 
     * @param i
     *                The integer specifying the position.
     * @return The SafeBag at position i.
     */
    public SafeContents getSafeContents(int i, char[] passwd)
	    throws IOException, ASN1Exception, GeneralSecurityException {
	// byte[] encodedData;
	ByteArrayInputStream bais;
	PBEKeySpec pbeSpec = null;
	byte[] data = null;
	EncryptedData encData = null;

	if (((ContentInfo) this.get(i)).getContent() instanceof EncryptedData) {
	    encData = (EncryptedData) ((ContentInfo) this.get(i)).getContent();
	} else {
	    System.out
		    .println("This bag is public-key protected or not protected at all.");
	    return null;
	}
	// "PbeWithSHAAnd40BitRC2_CBC";
	String algName = encData.getAlgorithm();

	// Create the PBEBMPKey ;
	pbeSpec = new PBEKeySpec(passwd);
	SecretKeyFactory skf = null;
	skf = SecretKeyFactory.getInstance(algName);
	SecretKey pbeKey = skf.generateSecret(pbeSpec);
	encData.init(pbeKey);
	data = encData.getData();
	bais = new ByteArrayInputStream(data);
	SafeContents safe = new SafeContents();
	BERDecoder decoder = new BERDecoder(bais);
	safe.decode(decoder);
	bais.close();
	return safe;
    }

    /**
     * returns the contents of the SafeBag in the AuthenticatedSafe at position
     * i, if the SafeBag is public-key-protected.
     * 
     * @param i
     *                The integer specifying the position.
     * @param key
     *                the private key for decrypting the content
     * @param cert
     *                the certificate corresponding to the private key
     * @return The SafeBag at position i.
     */
    public SafeContents getSafeContents(int i, java.security.PrivateKey key,
	    java.security.cert.X509Certificate cert) throws IOException,
	    ASN1Exception, GeneralSecurityException, NoSuchElementException {
	ByteArrayInputStream bais;

	ContentInfo cinfo = (ContentInfo) this.get(i);
	EnvelopedData envData = null;
	if (cinfo.getContent() instanceof EnvelopedData) {
	    envData = (EnvelopedData) cinfo.getContent();
	} else {
	    System.out
		    .println("This bag is password protected or not protected at all.");
	    return null;
	}

	envData.init(cert, key);
	byte[] data = envData.getData();

	bais = new ByteArrayInputStream(data);
	SafeContents safe = new SafeContents();
	BERDecoder decoder = new BERDecoder(bais);
	safe.decode(decoder);
	bais.close();
	return safe;
    }

    /**
     * returns a ContentInfo with contentType Data to feed to an
     * AuthenticatedSafe.
     * 
     * @return Contentinfo with contentType Data.
     */
    private ContentInfo makeData(SafeContents safe) throws IOException,
	    ASN1Exception {
	Data data = null;
	ByteArrayOutputStream baos = new ByteArrayOutputStream();
	DEREncoder encoder = new DEREncoder(baos);
	safe.encode(encoder);
	data = new Data(baos.toByteArray());
	baos.close();
	ContentInfo cInfo = new ContentInfo(data);
	return cInfo;
    }

    private ContentInfo makeEncryptedData(SafeContents safe, char[] pwd,
	    String algorithm) throws IOException, ASN1Exception,
	    GeneralSecurityException {
	ByteArrayOutputStream baos = new ByteArrayOutputStream();
	ByteArrayInputStream bais;
	DEREncoder encoder = new DEREncoder(baos);
	safe.encode(encoder);
	byte[] help = baos.toByteArray();

	// for ( int i = 0; i < help.length; i++)
	// System.out.print(help[i] + "\t");
	bais = new ByteArrayInputStream(help);
	baos.close();

	// Create the Parameters dor PBE
	byte[] salt = new byte[64];
	SecureRandom sr = new SecureRandom();
	sr.nextBytes(salt);

	PBEParameterSpec spec = new PBEParameterSpec(salt, 1);
	AlgorithmParameters params;

	params = AlgorithmParameters.getInstance(algorithm);
	params.init(spec);

	// Create a PBEKey
	PBEKeySpec pbeSpec = new PBEKeySpec(pwd);

	SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithm);
	SecretKey pbekey = skf.generateSecret(pbeSpec);

	// System.out.println("The pbe key for encrypting");
	// System.out.println(new ASN1OctetString(pbekey.getEncoded()));
	// make an EncryptedData and put it in a ContentInfo
	EncryptedData ecd = new EncryptedData(algorithm, pbekey, params);
	ecd.setData(bais);
	bais.close();

	ContentInfo cinfo = new ContentInfo();
	cinfo.setContent(new codec.asn1.ASN1ObjectIdentifier(
		"1.2.840.113549.1.7.6"), ecd);
	return cinfo;
    }

    private ContentInfo makeEnvelopedData(SafeContents safe, SecretKey key,
	    String algorithm, AlgorithmParameters params,
	    java.security.cert.X509Certificate[] cert) throws IOException,
	    GeneralSecurityException, BadNameException, ASN1Exception {
	// BER encode the SafeBag
	ByteArrayOutputStream baos = new ByteArrayOutputStream();
	ByteArrayInputStream bais;
	DEREncoder encoder = new DEREncoder(baos);
	safe.encode(encoder);
	bais = new ByteArrayInputStream(baos.toByteArray());
	baos.close();

	// Make an envelopedData and put it in a ContentInfo
	EnvelopedData edata = new EnvelopedData(key, algorithm, params);
	edata.setData(bais);
	bais.close();
	for (int i = 0; i < cert.length; i++) {
	    edata.addRecipient(cert[i]);
	}

	ContentInfo cinfo = new ContentInfo(edata);
	return cinfo;
    }

    /**
     * Returns a human-readable String representation of this object.
     * 
     * @return String representation of this object.
     */
    public String toString() {
	String res = "AuthenticatedSafe {\n";

	for (int i = 0; i < super.size(); i++) {
	    try {
		res = res + "SafeContents " + i + ": \n";

		if (((ContentInfo) this.get(i)).getContent() instanceof Data) {
		    res = res + getSafeContents(i) + "\n";
		} else if (((ContentInfo) this.get(i)).getContent() instanceof EncryptedData) {
		    res = res + "Password-Encrypted SafeBag \n";
		} else if (((ContentInfo) this.get(i)).getContent() instanceof EnvelopedData) {
		    res = res + "Public-Key-Encrypted SafeBag \n";
		}
	    } catch (Exception e) {
		res = res + "<SafeContent not printable>\n";
	    }
	}

	res = res + "}";
	return res;
    }
}
