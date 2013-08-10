/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.rsa;

import codec.asn1.ASN1Exception;
import codec.asn1.ASN1Null;
import codec.asn1.ASN1ObjectIdentifier;
import de.flexiprovider.api.MessageDigest;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.Signature;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.exceptions.SignatureException;
import de.flexiprovider.api.keys.PrivateKey;
import de.flexiprovider.api.keys.PublicKey;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.util.ByteUtils;
import de.flexiprovider.core.md.NullDigest;
import de.flexiprovider.core.rsa.interfaces.RSAPrivateKey;
import de.flexiprovider.core.rsa.interfaces.RSAPublicKey;
import de.flexiprovider.pki.AlgorithmIdentifier;

/**
 * The deterministic RSA signature algorithm RSASSA-PKCS1-v1_5, originally
 * defined in PKCS #1 v1.5, implemented as per <a
 * href=http://www.rsasecurity.com/rsalabs/pkcs/pkcs-1/index.html>PKCS#1 version
 * 2.1</a> with a variable message digest algorithm. EMSA-PKCS1-v1_5 (defined
 * in the IEEE P1363a draft) is used for message encoding, which embeds a hash
 * identifier in the signature. Whilst no attack against RSASSA-PKCS1-v1_5 is
 * currently known, it is suggested to move to RSASSA-PSS as a security
 * precaution (stronger theoretical security properties apply to RSASSA-PSS in
 * the random oracle model).
 * <p>
 * Subclassing it and overriding the <tt>getOID</tt> and
 * <tt>getMessageDigest</tt> methods yields the message digest specific
 * classes.
 * 
 * @author Thomas Wahrenbruch
 * @author Ralf-Philipp Weinmann
 */
public abstract class RSASignaturePKCS1v15 extends Signature {

    // the message digest
    private MessageDigest md;

    // the AlgorithmIdentifier for the DigestInfo structure
    private AlgorithmIdentifier aid;

    // the public key
    private RSAPublicKey pubKey;

    // the private key
    private RSAPrivateKey privKey;

    // the bit length of the modulus
    private int modBitLen;

    // //////////////////////////////////////////////////////////////////////////////

    /*
     * Inner classes providing concrete implementations of RSA PKCS#1 v1.5 with
     * a variety of message digests.
     */

    /**
     * RSA PKCS#1 v1.5 signature with MD5 message digest
     */
    public static class MD5 extends RSASignaturePKCS1v15 {

	/**
	 * The OID of MD5withRSA (defined by PKCS #1 v1.5).
	 */
	public static final String OID = "1.2.840.113549.1.1.4";

	/**
	 * An alternative OID of MD5withRSA (defined by SecSIG).
	 */
	public static final String ALTERNATIVE_OID = "1.3.14.3.2.25";

	public MD5() {
	    super(de.flexiprovider.core.md.MD5.OID,
		    new de.flexiprovider.core.md.MD5());
	}
    }

    /**
     * RSA PKCS#1 v1.5 signature with SHA-1 message digest
     */
    public static class SHA1 extends RSASignaturePKCS1v15 {

	/**
	 * The OID of MD5withRSA (defined by PKCS #1 v1.5).
	 */
	public static final String OID = "1.2.840.113549.1.1.5";

	/**
	 * An alternative OID of MD5withRSA (defined by SecSIG).
	 */
	public static final String ALTERNATIVE_OID = "1.3.14.3.2.29";

	public SHA1() {
	    super(de.flexiprovider.core.md.SHA1.OID,
		    new de.flexiprovider.core.md.SHA1());
	}
    }

    /**
     * RSA PKCS#1 v1.5 signature with SHA-224 message digest
     */
    public static class SHA224 extends RSASignaturePKCS1v15 {

	/**
	 * The OID of SHA224withRSA (defined by PKCS #1 v2.1).
	 */
	public static final String OID = "1.2.840.113549.1.1.14";

	public SHA224() {
	    super(de.flexiprovider.core.md.SHA224.OID,
		    new de.flexiprovider.core.md.SHA224());
	}
    }

    /**
     * RSA PKCS#1 v1.5 signature with SHA-256 message digest
     */
    public static class SHA256 extends RSASignaturePKCS1v15 {

	/**
	 * The OID of SHA256withRSA (defined by PKCS #1 v2.1).
	 */
	public static final String OID = "1.2.840.113549.1.1.11";

	public SHA256() {
	    super(de.flexiprovider.core.md.SHA256.OID,
		    new de.flexiprovider.core.md.SHA256());
	}
    }

    /**
     * RSA PKCS#1 v1.5 signature with SHA-384 message digest
     */
    public static class SHA384 extends RSASignaturePKCS1v15 {

	/**
	 * The OID of SHA384withRSA (defined by PKCS #1 v2.1).
	 */
	public static final String OID = "1.2.840.113549.1.1.12";

	public SHA384() {
	    super(de.flexiprovider.core.md.SHA384.OID,
		    new de.flexiprovider.core.md.SHA384());
	}
    }

    /**
     * RSA PKCS#1 v1.5 signature with SHA-512 message digest
     */
    public static class SHA512 extends RSASignaturePKCS1v15 {

	/**
	 * The OID of SHA512withRSA (defined by PKCS #1 v2.1).
	 */
	public static final String OID = "1.2.840.113549.1.1.13";

	public SHA512() {
	    super(de.flexiprovider.core.md.SHA512.OID,
		    new de.flexiprovider.core.md.SHA512());
	}
    }

    /**
     * RSA PKCS#1 v1.5 signature with RIPEMD-160 message digest
     */
    public static class RIPEMD160 extends RSASignaturePKCS1v15 {

	/**
	 * The OID of RIPEMD160withRSA (defined by TeleTrusT).
	 */
	public static final String OID = "1.3.36.3.3.1.2";

	public RIPEMD160() {
	    super(de.flexiprovider.core.md.RIPEMD160.OID,
		    new de.flexiprovider.core.md.RIPEMD160());
	}
    }

    // //////////////////////////////////////////////////////////////////////////////

    /**
     * RSA PKCS#1 v1.5 signature with MD5 message digest
     */
    public static class RawMD5 extends RSASignaturePKCS1v15 {
	public RawMD5() {
	    super(de.flexiprovider.core.md.MD5.OID, new NullDigest());
	}
    }

    /**
     * RSA PKCS#1 v1.5 signature with SHA-1 message digest
     */
    public static class RawSHA1 extends RSASignaturePKCS1v15 {
	public RawSHA1() {
	    super(de.flexiprovider.core.md.SHA1.OID, new NullDigest());
	}
    }

    /**
     * RSA PKCS#1 v1.5 signature with SHA-224 message digest
     */
    public static class RawSHA224 extends RSASignaturePKCS1v15 {
	public RawSHA224() {
	    super(de.flexiprovider.core.md.SHA224.OID, new NullDigest());
	}
    }

    /**
     * RSA PKCS#1 v1.5 signature with SHA-256 message digest
     */
    public static class RawSHA256 extends RSASignaturePKCS1v15 {
	public RawSHA256() {
	    super(de.flexiprovider.core.md.SHA256.OID, new NullDigest());
	}
    }

    /**
     * RSA PKCS#1 v1.5 signature with SHA-384 message digest
     */
    public static class RawSHA384 extends RSASignaturePKCS1v15 {
	public RawSHA384() {
	    super(de.flexiprovider.core.md.SHA384.OID, new NullDigest());
	}
    }

    /**
     * RSA PKCS#1 v1.5 signature with SHA-512 message digest
     */
    public static class RawSHA512 extends RSASignaturePKCS1v15 {
	public RawSHA512() {
	    super(de.flexiprovider.core.md.SHA512.OID, new NullDigest());
	}
    }

    /**
     * RSA PKCS#1 v1.5 signature with RIPEMD-160 message digest
     */
    public static class RawRIPEMD160 extends RSASignaturePKCS1v15 {
	public RawRIPEMD160() {
	    super(de.flexiprovider.core.md.RIPEMD160.OID, new NullDigest());
	}
    }

    /**
     * Constructor. Generate the RSA-SSA-PSS algorithm identifier with the
     * corresponding OID.
     * 
     * @param oidStr
     *                the OID
     * @param md
     *                the message digest
     */
    protected RSASignaturePKCS1v15(String oidStr, MessageDigest md) {
	try {
	    aid = new AlgorithmIdentifier(new ASN1ObjectIdentifier(oidStr),
		    new ASN1Null());
	} catch (ASN1Exception ae) {
	    throw new RuntimeException("Internal error in CoDec.");
	}
	this.md = md;
    }

    /**
     * Initializes the signature algorithm for signing a message.
     * 
     * @param privateKey
     *                the private key of the signer.
     * @param secureRandom
     *                the source of randomness.
     * @throws InvalidKeyException
     *                 if the key is not an instance of RSAPrivKey.
     */
    public void initSign(PrivateKey privateKey, SecureRandom secureRandom)
	    throws InvalidKeyException {
	if (!(privateKey instanceof RSAPrivateKey)) {
	    throw new InvalidKeyException("key is not a RSAPrivateKey.");
	}

	privKey = (RSAPrivateKey) privateKey;
	modBitLen = privKey.getN().bitLength();
    }

    /**
     * Initializes the signature algorithm for verifying a signature.
     * 
     * @param publicKey
     *                the public key of the signer.
     * @throws InvalidKeyException
     *                 if the public key is not an instance of RSAPubKey.
     */
    public void initVerify(PublicKey publicKey) throws InvalidKeyException {
	if (!(publicKey instanceof RSAPublicKey)) {
	    throw new InvalidKeyException("key is not a RSAPublicKey.");
	}

	pubKey = (RSAPublicKey) publicKey;
	modBitLen = pubKey.getN().bitLength();
    }

    /**
     * Set parameters for the signature (not used).
     * 
     * @param params
     *                the parameters (not used)
     */
    public void setParameters(AlgorithmParameterSpec params) {
	// empty
    }

    /**
     * Feeds message bytes to the message digest.
     * 
     * @param b
     *                array of message bytes
     * @param offset
     *                index of message start
     * @param length
     *                number of message bytes
     */
    public void update(byte[] b, int offset, int length) {
	md.update(b, offset, length);
    }

    /**
     * Feeds a message byte to the message digest.
     * 
     * @param b
     *                array of message bytes
     */
    public void update(byte b) {
	md.update(b);
    }

    /**
     * Signs a message.
     * 
     * @return the signature.
     * @throws SignatureException
     *                 if the signature is not initialized properly.
     */
    public byte[] sign() throws SignatureException {
	FlexiBigInt s, m;
	int k = (modBitLen + 7) >> 3;
	byte[] EM;

	// 1) EMSA-PKCS1-v1_5 encoding: Apply the EMSA-PKCS1-v1_5 encoding
	// operation to the
	// message M to produce an encoded message EM of length k octets:
	// EM = EMSA-PKCS1-v1_5-ENCODE(M, k).
	try {
	    EM = PKCS1Operations.EMSA_PKCS1_v1_5_ENCODE(md.digest(), k, aid);
	} catch (PKCS1Exception pkcs1e) {
	    // If the encoding operation outputs "message too long", output
	    // "message too long"
	    // and stop. If the encoding operation outputs "encoding error",
	    // output
	    // "encoding error" and stop.
	    throw new SignatureException(pkcs1e.getMessage());
	}

	// 2) RSA signature:
	// a) Convert the encoded message EM to an integer message
	// representative m = OS2IP (EM).
	m = PKCS1Operations.OS2IP(EM);

	// b) b. Apply the RSASP1 signature primitive (equivalent to RSADP) to
	// the
	// RSA private key K and the message representative m to produce an
	// integer
	// signature representative s = RSASP1 (K, m)
	try {
	    s = PKCS1Operations.RSADP(privKey, m);
	} catch (PKCS1Exception pkcs1e) {
	    throw new SignatureException("encoding error.");
	}

	// c) Convert the signature representative s to a signature S of length
	// k octets:
	// S = I2OSP (s, k)
	// 3) Output the signature S.
	try {
	    return PKCS1Operations.I2OSP(s, k);
	} catch (PKCS1Exception pkcs1e) {
	    throw new SignatureException("internal error.");
	}
    }

    /**
     * Verifies a signature.
     * 
     * @param signature
     *                the signature to be verified
     * @return true if the signature is correct - false otherwise.
     */
    public boolean verify(byte[] signature) {
	FlexiBigInt m, s;
	byte[] EM, EM2;
	int k = (modBitLen + 7) >> 3;

	// 1) Length checking: If the length of the signature S is not
	// k octets, output "invalid signature" and stop.
	if (signature.length != k) {
	    return false;
	}

	// 2) RSA verification:
	// a) Convert the signature S to an integer signature representative s
	s = PKCS1Operations.OS2IP(signature);

	try {
	    // b) Apply the RSAVP1 verification primitive to the RSA public key
	    // (n, e)
	    // and the signature representative s to produce an integer message
	    // representative m:
	    m = PKCS1Operations.RSAEP(pubKey, s);
	    // c) Convert the message representative m to an encoded message EM
	    // of length
	    // k octets: EM = I2OSP (m, k)
	    EM = PKCS1Operations.I2OSP(m, k);
	    // 3) EMSA-PKCS1-v1_5 encoding: Apply the EMSA-PKCS1-v1_5 encoding
	    // operation to the
	    // message M to produce an encoded message EM2 of length k octets:
	    // EM2 = EMSA-PKCS1-v1_5-ENCODE(M, k).
	    EM2 = PKCS1Operations.EMSA_PKCS1_v1_5_ENCODE(md.digest(), k, aid);
	} catch (PKCS1Exception pkcs1e) {
	    // if anything goes wrong, we consider the signature invalid.
	    return false;
	}

	// 4. Compare the encoded message EM and the second encoded message EM2.
	// If they
	// are the same, output "valid signature"; otherwise, output "invalid
	// signature".
	return ByteUtils.equals(EM, EM2);
    }

}
