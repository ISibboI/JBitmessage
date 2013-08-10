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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import codec.asn1.ASN1Exception;
import codec.asn1.ASN1Integer;
import codec.asn1.ASN1Null;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1Type;
import codec.asn1.BERDecoder;
import codec.asn1.DERDecoder;
import codec.asn1.DEREncoder;
import codec.asn1.Decoder;
import codec.pkcs1.DigestInfo;
import codec.pkcs7.ContentInfo;
import codec.pkcs7.Data;
import codec.pkcs7.SignedData;
import codec.pkcs7.SignerInfo;
import codec.pkcs7.Verifier;
import codec.x501.BadNameException;
import codec.x509.AlgorithmIdentifier;

/**
 * This class represents a <code>PFX</code> as defined in <a
 * href="http://www.rsasecurity.com/rsalabs/pkcs/pkcs-12/index.html"> PKCS#12</a>.
 * The ASN.1 definition of this structure is
 * <p>
 * 
 * <pre>
 *  PFX ::= SEQUENCE {
 *   version     INTEGER{v3(3)}(v3,...),
 *   authSafe    ContentInfo,
 *   macData     MacData OPTIONAL
 * }
 * MacData ::= SEQUENCE {
 *   mac         DigestInfo,
 *   macSalt     OCTET STRING,
 *   iterations  INTEGER DEFAULT 1
 *   --NOTE: The default is for historical reasons and its use is deprecated.
 *           A higher value like 1024 is recommended.
 * </pre>
 * 
 * <p>
 * <code>PFX</code> The PFX is the outer integrity wrapper of a PDU.
 * <p>
 * To create a PKCS#12 file that can be read by Netscape or Internet Explorer,
 * do the following:
 * 
 * <pre>
 * PrivateKey priv = ...;
 * PublicKey pub = ...;
 * X509Certificate cert = ...;
 * char[] password = ...; // this password protects both privacy and integrity
 * PFX myPFX = new PFX( priv, cert, null, password, &quot;My Certificate&quot;, null);
 * DEREncoder enc = new DEREncoder(new FileOutputStream(&quot;myCert.p12&quot;));
 * myPFX.encode(enc);
 * enc.close(); 
 * </pre>
 * 
 * @author Michele Boivin
 * @version "$Id: PFX.java,v 1.2 2004/08/12 14:50:20 pebinger Exp $"
 */
public class PFX extends ASN1Sequence implements java.io.Serializable {

    /**
     * The PFX Version Number.
     */
    protected static ASN1Integer version_;

    /**
     * The actual content of this structure.
     */
    protected ContentInfo authSafe_;

    /**
     * The mac data that protects the integrity of the PFX in
     * password-based-integrity- mode.
     */
    protected MacData macData_;

    /**
     * The authenticated Safe in this structure
     */
    private AuthenticatedSafe authentSafe_;

    /**
     * The OID for the SHA Hashfunction
     */
    private int[] SHA_OID = { 1, 3, 14, 3, 2, 26 };

    /**
     * for PFX with no integrity mode
     */
    public static final int INTEGRITY_MODE_NONE = 0;

    /**
     * for PFX protected in password integrity mode
     */
    public static final int INTEGRITY_MODE_PASSWORD = 1;

    /**
     * for PFX protected in public key integrity mode
     */
    public static final int INTEGRITY_MODE_PUBLIC_KEY = 2;

    /**
     * holds the current integrity mode
     */
    protected int INTEGRITY_MODE_;

    /**
     * This constructor builds the tree of ASN.1 objects used for decoding this
     * structure. This structure should be decoded using the {@link DERDecoder}
     * of the asn1 package.
     */
    public PFX() {
	version_ = new ASN1Integer();
	add(version_);

	authSafe_ = new ContentInfo();
	add(authSafe_);

	macData_ = new MacData();
	macData_.setOptional(true);
	add(macData_);
    }

    /**
     * This constructor creates a PFX without integrity protection. Use of
     * integrity protection is strongly encouraged!
     * 
     * @throws ASN1Exception
     *                 if the authSafe could not be encoded
     */
    public PFX(AuthenticatedSafe authSafe) throws ASN1Exception {
	version_ = new ASN1Integer(3);
	add(version_);

	// Encode the authSafe and place it in a ContentInfo
	// as type data.
	setAuthenticatedSafe(authSafe);

	INTEGRITY_MODE_ = INTEGRITY_MODE_NONE;
    }

    /**
     * This constructor takes an authenticated safe and creates a PFX PDU that
     * is protected through password-integrity-mode.
     * 
     * @param authSafe
     *                The AuthenticatedSafe to be wrapped in a PFX PDU.
     * @param pwd
     *                The password used to ensure the integrity of the PFX PDU.
     * @throws ASN1Exception
     *                 if the authSafe could not be encoded
     * @throws NoSuchAlgorithmException
     *                 if the HMAC algorithms is not available
     * @throws InvalidKeySpecException
     *                 if there was a problem with the HMAC
     * @throws InvalidKeyException
     *                 if there was a problem with the HMAC
     * @throws InvalidAlgorithmParameterException
     *                 if there was a problem with the HMAC
     */
    public PFX(AuthenticatedSafe authSafe, char[] pwd) throws ASN1Exception,
	    NoSuchAlgorithmException, InvalidKeySpecException,
	    InvalidKeyException, InvalidAlgorithmParameterException {
	version_ = new ASN1Integer(3);
	add(version_);

	// Encode the authenticated safe and put it in a
	// contentInfo as type data.
	setAuthenticatedSafe(authSafe);

	// compute the HMAC/SHA1 of the Data and the password.
	addMacData(pwd);

	INTEGRITY_MODE_ = INTEGRITY_MODE_PASSWORD;
    }

    /**
     * This constructor takes an authenticated safe and creates a PFX PDU that
     * is protected by public-key-integrity-mode. The pdu is protected by
     * signing the authenticated safe.
     * 
     * @param authSafe
     *                the authenticated safe that shall be secured in a pdu.
     * @param pk
     *                the private key that is used to sign the pdu.
     * @param cert
     *                the corresponding certificate to the private key.
     * @param sigAlgName
     *                the signature algorithm name
     * @param params
     *                the parameters needed for the signature algorithm. if no
     *                parameters are needed params should be null.
     * @throws SignatureException
     *                 if there was a problem with the signing of the PFX pdu
     * @throws GeneralSecurityException
     *                 if some general problem with the signing occured
     * @throws ASN1Exception
     *                 if the authSafe could not be encoded
     */
    public PFX(AuthenticatedSafe authSafe, PrivateKey pk, X509Certificate cert,
	    String sigAlgName, AlgorithmParameters params)
	    throws SignatureException, GeneralSecurityException, ASN1Exception {
	byte[] data = null;
	SignedData signedData;
	SignerInfo signerInfo;
	ByteArrayOutputStream baos;
	DEREncoder encoder;
	codec.pkcs7.Signer sig;

	version_ = new ASN1Integer(3);
	add(version_);

	try {
	    baos = new ByteArrayOutputStream();
	    encoder = new DEREncoder(baos);
	    authSafe.encode(encoder);
	    data = baos.toByteArray();
	    baos.close();

	    signedData = new SignedData();
	    signedData.setData(data);

	    signerInfo = new SignerInfo(cert, sigAlgName, params);
	    sig = new codec.pkcs7.Signer(signedData, signerInfo, pk);

	    sig.update();
	    sig.sign();
	    authSafe_ = new ContentInfo(signedData);
	    add(authSafe_);

	    INTEGRITY_MODE_ = INTEGRITY_MODE_PUBLIC_KEY;
	} catch (IOException io) {
	    System.out.println("Internal Error. Shouldn't occur:");
	    io.printStackTrace();
	    throw new GeneralSecurityException("Caught IOException: "
		    + io.getMessage());
	} catch (BadNameException io) {
	    System.out.println("Internal Error. Shouldn't occur:");
	    io.printStackTrace();
	    throw new GeneralSecurityException("Caught BadNameException: "
		    + io.getMessage());
	}

    }

    /**
     * This constructor is for the convenient use of a PFX PDU for PKCS#12 files
     * that can be imported by Netscape or Internet Explorer. It takes a private
     * key, a certificate (optionally with a certificate chain) and a pin and
     * creates a SafeContents for the key and the certificates. The private key
     * will be password encrypted with the pin using
     * PbeWithSHAAnd3_KeyTripleDES_CBC and saved in a PKCS8ShroudedKeyBag. The
     * certificates are packed into certificate bags. The bags are saved in a
     * password protected AuthenticatedSafe using PbeWithSHAAnd40BitRC2_CBC and
     * the pin.
     * 
     * @param pr_key
     *                the private key.
     * @param cert
     *                The certificate corresponding to the private key
     * @param chain
     *                The certificate chain up to the root CA (excluding the
     *                certificate passed in cert). If no chain is used, just
     *                pass null
     * @param pin
     *                The password to encrypt and integrity-protect this PFX
     * @param user_fn
     *                the user friendlyName attribute (can be null)
     * @param lk_id
     *                the localKeyId attribute (can be null)
     * 
     * @throws GeneralSecurityException
     *                 if there was a general problem with the signature
     * @throws CertificateEncodingException
     *                 if there was a problem with the certificate
     * @throws ASN1Exception
     *                 if some ASN1 type could not be encoded properly
     */
    public PFX(PrivateKey pr_key, X509Certificate cert,
	    X509Certificate[] chain, char[] pin, String user_fn, byte[] lk_id)
	    throws GeneralSecurityException, CertificateEncodingException,
	    ASN1Exception {
	try {
	    // Construct a SafeContents with the given certificate
	    SafeContents sc_cert = new SafeContents(new CertBag(cert), user_fn,
		    lk_id);

	    // add the chain if it was given
	    if (chain != null) {
		for (int i = 0; i < chain.length; i++) {
		    sc_cert.addSafeBag(new CertBag(chain[i]));
		}
	    }

	    // Construct a SafeContents with a PKCS8ShroudedKeyBag for
	    // the private key.
	    PKCS8ShroudedKeyBag kb = new PKCS8ShroudedKeyBag();
	    kb.setPrivateKey(pr_key, pin, "PbeWithSHAAnd3_KeyTripleDES_CBC");
	    SafeContents sc = new SafeContents(kb, user_fn, lk_id);

	    // Construct an AuthenticatedSafe to hold the SafeContents
	    // (keys + certificates)
	    AuthenticatedSafe authSafe = new AuthenticatedSafe(sc);
	    authSafe.addSafeContents(sc_cert, pin, "PbeWithSHAAnd40BitRC2_CBC");

	    // Put it in a PFX and integrity-protect it with MacData.
	    version_ = new ASN1Integer(3);
	    add(version_);
	    setAuthenticatedSafe(authSafe);
	    addMacData(pin);

	    // exception handling
	} catch (IOException e) {
	    System.out.println("Internal Error. Shouldn't occur:");
	    e.printStackTrace();
	    throw new GeneralSecurityException("Caught IOException: "
		    + e.getMessage());
	}
    }

    /**
     * Encodes the authenticated Safe and saves it as data in a ContentInfo.
     * 
     * @throws ASN1Exception
     *                 if the authSafe could not be properly encoded
     */
    private void setAuthenticatedSafe(AuthenticatedSafe authSafe)
	    throws ASN1Exception {
	byte[] rawdata;
	try {
	    ByteArrayOutputStream baos = new ByteArrayOutputStream();
	    DEREncoder encoder = new DEREncoder(baos);
	    authentSafe_ = authSafe;
	    authentSafe_.encode(encoder);
	    rawdata = baos.toByteArray();
	    baos.close();
	    Data data = new Data(rawdata);
	    authSafe_ = new ContentInfo(data);
	    add(authSafe_);
	} catch (IOException e) {
	    System.out.println("Internal Error. Should not occur:");
	    e.printStackTrace();
	}
    }

    /**
     * This function takes the passphrase from the PBEKey and the salt according
     * to the key generation scheme described in PKCS12.
     * 
     * @param pbeKey
     *                the PBEKey
     * @param salt
     *                the salt
     * @param iterationCount
     *                the iteration count
     * @return the bytes representing a key for the underlying cipher.
     */
    private byte[] generateKeyBytes(SecretKey pbeKey, byte[] salt,
	    int iterationCount) throws NoSuchAlgorithmException {
	MessageDigest md = MessageDigest.getInstance("SHA1");
	// the byte array representation of the PBEKey
	byte[] passwd = pbeKey.getEncoded();

	// v = 64 bytes
	// Construct a string, D (the "diversifier") by concatenating
	// v/8 copies of of ID. ID is 1, if the derived bits are to
	// be used for encryption or decryption.
	byte[] mD = new byte[64];
	for (int i = 0; i < mD.length; i++)
	    mD[i] = 3;

	// Concatenate copies of the salt/password to create a string S
	// (or P)of length v * ceil(s (or p)/v).
	byte[] mP = augment(passwd, 64);
	byte[] mS = augment(salt, 64);

	// Concatenate S and P to obtain a string I = S||P.
	byte[] mI = new byte[mP.length + mS.length];
	System.arraycopy(mS, 0, mI, 0, mS.length);
	System.arraycopy(mP, 0, mI, mS.length, mP.length);

	// the pseudo-random bitstring
	byte[] mA;

	// compute H(H(H(...H(D||I))))
	md.update(mD);
	md.update(mI);
	mA = md.digest();

	for (int i = 1; i < iterationCount; i++) {
	    md.update(mA);
	    mA = md.digest();
	}

	return mA;
    }

    private byte[] augment(byte[] in, int v) {
	int n, tmp, amount, iter;
	byte[] out;

	n = in.length;
	tmp = (n + v - 1) / v;
	amount = v * tmp;
	out = new byte[amount];
	iter = amount / n;

	for (int i = 0; i < iter; i++)
	    System.arraycopy(in, 0, out, i * n, n);

	if (amount % n != 0)
	    System.arraycopy(in, 0, out, iter * n, amount % n);

	return out;
    }

    /**
     * Computes the HmacData and stores it in the PFX.
     * 
     * @param pwd
     *                the password to compute the integrity digest
     * 
     * @throws NoSuchAlgorithmException
     *                 if the algorithm "PbeWithSHAAnd3_KeyTripleDES_CBC" was
     *                 not available
     * @throws InvalidKeySpecException
     *                 if there was a problem with the HMAC
     * @throws InvalidKeyException
     *                 if there was a problem with the HMAC
     * @throws ASN1Exception
     *                 if encoding failed
     */
    private void addMacData(char[] pwd) throws NoSuchAlgorithmException,
	    InvalidKeySpecException, InvalidKeyException,
	    InvalidAlgorithmParameterException, ASN1Exception {
	byte[] rawdata;
	DigestInfo digest;
	int iter;

	try {

	    iter = 1024;
	    byte[] salt = new byte[64];
	    SecureRandom sr = new SecureRandom();
	    sr.nextBytes(salt);

	    PBEKeySpec pbeSpec = new PBEKeySpec(pwd);

	    SecretKeyFactory skf = SecretKeyFactory
		    .getInstance("PbeWithSHAAnd3_KeyTripleDES_CBC");
	    SecretKey pbeKey = skf.generateSecret(pbeSpec);
	    byte[] keyBytes = generateKeyBytes(pbeKey, salt, iter);

	    Mac hmac = Mac.getInstance("HmacSHA1");
	    hmac.init(new SecretKeySpec(keyBytes, "HmacSHA1"), null);

	    // the data to be MACed
	    ByteArrayOutputStream baos = new ByteArrayOutputStream();
	    DEREncoder encoder = new DEREncoder(baos);
	    authentSafe_.encode(encoder);
	    rawdata = baos.toByteArray();
	    baos.close();

	    byte[] macData = hmac.doFinal(rawdata);
	    AlgorithmIdentifier algId = new AlgorithmIdentifier(
		    new ASN1ObjectIdentifier(SHA_OID), new ASN1Null());
	    digest = new DigestInfo(algId, macData);

	    macData_ = new MacData(digest, salt, iter);
	    add(macData_);

	    INTEGRITY_MODE_ = INTEGRITY_MODE_PASSWORD;

	} catch (IOException e) {
	    System.out.println("Internal Error. Should not occur:");
	    e.printStackTrace();
	}
    }

    /**
     * verifies the the Hmac of this PFX if INTEGRITY_MODE_PASSWORD was used.
     * 
     * @param pwd
     *                the password protecting the pdu
     * @return true if the password integrity check was correct
     * @throws NoSuchAlgorithmException
     *                 if the HMAC algorithm is not available
     * @throws InvalidAlgorithmParameterException
     *                 if there was a problem with the HMAC
     * @throws InvalidKeyException
     *                 if there was a problem with the HMAC
     * @throws InvalidKeySpecException
     *                 if there was a problem with the HMAC
     * @throws IllegalStateException
     *                 if there this PFX is not protected by
     *                 INTEGRITY_MODE_PASSWORD
     */
    public boolean checkIntegrity(char[] pwd) throws NoSuchAlgorithmException,
	    InvalidAlgorithmParameterException, InvalidKeyException,
	    InvalidKeySpecException {
	byte[] dataToVerify;

	if (INTEGRITY_MODE_ != INTEGRITY_MODE_PASSWORD)
	    throw new IllegalStateException(
		    "bad integrity mode (not password integrity)!");

	// the data to be verified
	dataToVerify = macData_.getMacData().getDigest();

	// construct a PBE Key
	PBEKeySpec keySpec = new PBEKeySpec(pwd);
	SecretKeyFactory skf = SecretKeyFactory
		.getInstance("PbeWithSHAAnd3_KeyTripleDES_CBC");
	SecretKey key = skf.generateSecret(keySpec);

	// compute the hmac
	Mac hmac = Mac.getInstance("HmacSHA1");

	PBEParameterSpec params = new PBEParameterSpec(macData_.getSalt(),
		macData_.getIterationCount());
	hmac.init(key, params);
	byte[] data = ((Data) authSafe_.getContent()).getByteArray();
	byte[] macData = hmac.doFinal(data);
	// compare the macData with the newly computed hmac data
	boolean value = true;
	for (int i = 0; i < macData.length; i++) {
	    if ((macData[i] == dataToVerify[i]) && (value == true))
		value = true;
	    else
		value = false;
	}
	return value;

    }

    /**
     * verifies the signature of the AuthenticatedSafe if
     * INTEGRITY_MODE_PUBLIC_KEY was used.
     * 
     * @param cert
     *                the certificate with the public-key to verify the
     *                signature on the AuthenticatedSafe.
     * @return X509Certificate if signature is valid, null if not.
     * @throws GeneralSecurityException
     *                 if there was a problem with the signature
     */
    public java.security.cert.X509Certificate checkIntegrity(
	    X509Certificate cert) throws GeneralSecurityException {
	if (INTEGRITY_MODE_ != INTEGRITY_MODE_PUBLIC_KEY)
	    throw new IllegalStateException(
		    "bad integrity mode (not password integrity)!");

	SignedData sigDat = (SignedData) authSafe_.getContent();
	Verifier ver = new Verifier(sigDat, null, cert);
	ver.update();
	return (ver.verify());
    }

    /**
     * Decodes this structure. This structure should be decoded with a
     * {@link BERDecoder}.
     */
    public void decode(Decoder dec) throws ASN1Exception, IOException {
	super.decode(dec);

	if (macData_ != null)
	    INTEGRITY_MODE_ = INTEGRITY_MODE_PASSWORD;
	else if (authSafe_.getContent() instanceof SignedData)
	    INTEGRITY_MODE_ = INTEGRITY_MODE_PUBLIC_KEY;
	else
	    INTEGRITY_MODE_ = INTEGRITY_MODE_NONE;
    }

    /**
     * This method returns the AuthenticatedSafe structure inside this PFX PDU
     * 
     * @return the AuthenticatedSafe structure
     * @throws IllegalStateException
     *                 if there were no data
     * @throws ASN1Exception
     *                 if the authSafe could not proberly be decoded
     */
    public AuthenticatedSafe getAuthSafe() throws ASN1Exception,
	    IllegalStateException {
	ByteArrayInputStream bais;
	byte[] encodedData;

	if (authSafe_.getContent() instanceof Data)
	    encodedData = ((Data) authSafe_.getContent()).getByteArray();
	else {
	    if (authSafe_.getContent() instanceof SignedData) {
		ASN1Type content = ((SignedData) authSafe_.getContent())
			.getContent();
		if (content instanceof Data)
		    encodedData = ((Data) content).getByteArray();
		else
		    throw new IllegalStateException(
			    "unable to extract authSafe encoded data!");
	    } else {
		throw new IllegalStateException(
			"The contents of the PFX is not a valid type.");
	    }
	}

	bais = new ByteArrayInputStream(encodedData);
	authentSafe_ = new AuthenticatedSafe();
	try {
	    BERDecoder decoder = new BERDecoder(bais);
	    authentSafe_.decode(decoder);
	    bais.close();
	} catch (IOException e) {
	    System.out.println("Internal Error. Should not occur:");
	    e.printStackTrace();
	}
	return authentSafe_;
    }

    /**
     * Returns the integrity protection mode. This can either be
     * INTEGRITY_MODE_NONE, INTEGRITY_MODE_PASSWORD or INTEGRITY_MODE_PUBLIC_KEY
     */
    public int getIntegrityMode() {
	return INTEGRITY_MODE_;
    }

    /**
     * This method returns the version number of this structure.
     */
    public ASN1Integer getVersion() {
	return version_;
    }

    /**
     * Returns a human-readable String representation of this object.
     */
    public String toString() {
	String res = "PFX {\n";
	res = res + " Version: " + version_.getBigInteger().toString() + "\n";

	try {
	    res = res + " " + getAuthSafe().toString() + "\n";
	} catch (Exception e) {
	    res = res + " <AuthenticatedSafe not printable. Caught "
		    + e.getClass().getName() + ">\n";
	}

	if (macData_ == null)
	    res = res + " No MacData\n";
	else {
	    try {
		res = res + " MacData: " + macData_.toString() + "\n";
	    } catch (Exception e) {
		res = res + " <MacData not printable. Caught "
			+ e.getClass().getName() + ">\n";
	    }
	}

	if (INTEGRITY_MODE_ == INTEGRITY_MODE_NONE)
	    res = res + "NO INTEGRITY PROTECTION\n";
	else if (INTEGRITY_MODE_ == INTEGRITY_MODE_PASSWORD)
	    res = res + "Integrity is guaranteed by password integrity mode\n";
	else if (INTEGRITY_MODE_ == INTEGRITY_MODE_PUBLIC_KEY)
	    res = res
		    + "Integrity is guaranteed by public-key integrity mode\n";

	res = res + "}";
	return res;
    }
}
