/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.mersa;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import de.flexiprovider.api.MessageDigest;
import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.Signature;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.exceptions.NoSuchAlgorithmException;
import de.flexiprovider.api.exceptions.SignatureException;
import de.flexiprovider.api.keys.PrivateKey;
import de.flexiprovider.api.keys.PublicKey;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.core.rsa.PKCS1Exception;
import de.flexiprovider.core.rsa.PKCS1Operations;
import de.flexiprovider.core.rsa.PSSParameterSpec;
import de.flexiprovider.core.rsa.interfaces.RSAPublicKey;

/**
 * MeRSASSA-PSS (MeRSA Signature Scheme with Appendix - Probabilistic Signature
 * Scheme) is an asymmetric signature scheme with appendix combining the MeRSA
 * algorithm with the PSS encoding method. The PSS encoding method was invented
 * by Mihir Bellare and Phillip Rogaway.
 * 
 * @author Erik Dahmen
 * @author Paul Nguentcheu
 */
public class MeRSASignaturePSS extends Signature {

    /**
     * the algorithm parameters
     */
    private PSSParameterSpec params;

    /**
     * the message digest
     */
    private MessageDigest md;

    /**
     * source of randomness
     */
    SecureRandom random;

    /**
     * size of a cipher block.
     */
    private int cipherBlockSize;

    /**
     * bit length of the RSA modulus
     */
    private int modBits;

    /**
     * reference to the public key
     */
    private RSAPublicKey pubKey;

    /**
     * reference to the private key
     */
    private MeRSAPrivateKey privKey;

    /**
     * instance of <code>ByteArrayOutputStream</code> used as a buffer object
     * for accumulating input bytes passed to <code>engineUpdate</code>. this
     * is necessary because we do not know the salt value beforehand for the
     * verification case.
     */
    private ByteArrayOutputStream baos;

    /**
     * The default constructor generates an <code>AlgorithmIdentifier</code>
     * object for MeRSASSA-PSS with OID 1.2.840.113549.1.1.10. Failure to
     * achieve this is fatal and will result in a <code>RuntimeException</code>
     */
    public MeRSASignaturePSS() {
	params = new PSSParameterSpec();
    }

    /**
     * Set the algorithm parameters.
     * 
     * @param params
     *                the algorithm parameters
     * @throws InvalidAlgorithmParameterException
     *                 if <tt>params</tt> is not an instance of
     *                 {@link de.flexiprovider.core.rsa.PSSParameterSpec}.
     */
    protected final void engineSetParameter(AlgorithmParameterSpec params)
	    throws InvalidAlgorithmParameterException {
	if (!(params instanceof PSSParameterSpec)) {
	    throw new InvalidAlgorithmParameterException(
		    "params is not a PSSParameterSpec");
	}

	this.params = (PSSParameterSpec) params;
    }

    /**
     * Initializes the signature algorithm for either signing or verifying a
     * message
     */
    private void initCommon() throws InvalidKeyException {
	try {
	    md = Registry.getMessageDigest(params.getMD());
	} catch (NoSuchAlgorithmException nsae) {
	    throw new InvalidKeyException(
		    "message digest SHA1 not found (key may be valid nonetheless).");
	}
	cipherBlockSize = (modBits + 7) >> 3;
	baos = new ByteArrayOutputStream();
    }

    /**
     * Initializes the signature algorithm for signing a message.
     * 
     * @param privateKey
     *                the private key of the signer
     * @param random
     *                the source of randomness
     * @throws InvalidKeyException
     *                 if the key is not an instance of MeRSAPrivateKey
     */
    public void initSign(PrivateKey privateKey, SecureRandom random)
	    throws InvalidKeyException {

	if (!(privateKey instanceof MeRSAPrivateKey)) {
	    throw new InvalidKeyException(
		    "key is not an instance of MeRSAPrivateKey");
	}

	privKey = (MeRSAPrivateKey) privateKey;
	modBits = privKey.getN().bitLength();

	// make sure that a source of randomness exists
	if (random != null) {
	    this.random = random;
	} else {
	    this.random = Registry.getSecureRandom();
	}
	initCommon();
    }

    /**
     * Initializes the signature algorithm for verifying a signature.
     * 
     * @param publicKey
     *                the public key of the signer.
     * @throws InvalidKeyException
     *                 if the public key is not an instance of RSAPublicKey.
     */
    public void initVerify(PublicKey publicKey) throws InvalidKeyException {
	if (publicKey instanceof RSAPublicKey) {
	    pubKey = (RSAPublicKey) publicKey;
	    modBits = pubKey.getN().bitLength();
	} else {
	    throw new InvalidKeyException(
		    "key is not an instance of RSAPublicKey");
	}
	initCommon();
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
     * Writes a byte into the ByteArrayOutputStream.
     * 
     * @param b
     *                the message byte.
     */
    public void update(byte b) {
	baos.write(b);
    }

    /**
     * Writes length bytes beginning at offset into the ByteArrayOutputStream.
     * 
     * @param b
     *                The message byte.
     * @param offset
     *                The index, where the message bytes starts.
     * @param length
     *                The number of message bytes.
     */
    public void update(byte[] b, int offset, int length) {
	baos.write(b, offset, length);
    }

    /**
     * Returns the data accumulated in the <code>ByteArrayOutputStream</code>
     * object which is fed by <code>engineUpdate</code> as an octet string.
     * 
     * @return octet string representing the message
     */
    private byte[] getMessage() throws IOException {
	byte[] msg = baos.toByteArray();

	baos.close();
	baos.reset();

	return msg;
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
	byte[] EM;

	// 1) EMSA-PSS encoding: Apply the EMSA-PSS encoding operation to the
	// message M to produce an encoded message EM of length
	// ceil((modBits-1)/8)
	// octets such that the bit length of the integer OS2IP (EM) is at most
	// modBits-1,
	// where modBits is the length in bits of the RSA modulus n:
	// EM = EMSA-PSS-ENCODE (M, modBits-1).
	// Note that the octet length of EM will be one less than k if modBits-1
	// is
	// divisible by 8 and equal to k otherwise.
	try {
	    byte[] salt = new byte[params.getSaltLength()];
	    random.nextBytes(salt);
	    EM = PKCS1Operations.EMSA_PSS_ENCODE(getMessage(), modBits - 1, md,
		    salt);
	} catch (PKCS1Exception pkcs1e) {
	    // If the encoding operation outputs "message too long", output
	    // "message too long" and stop. If the encoding operation outputs
	    // "encoding error", output "encoding error" and stop.
	    throw new SignatureException(pkcs1e.getMessage());
	} catch (IOException ioe) {
	    throw new SignatureException(ioe.getMessage());
	}

	// 2) MeRSA Operation:
	// a) Convert the encoded message EM to an integer message
	// representative m = OS2IP (EM).
	m = PKCS1Operations.OS2IP(EM);

	// b) b. Apply the MeRSASP1 signature primitive (equivalent to MeRSADP)
	// to
	// the
	// MeRSA private key K and the message representative m to produce an
	// integer
	// signature representative s = MeRSASP1 (K, m)
	try {
	    s = MeRSAOperations.MeRSADP(privKey, m);
	} catch (PKCS1Exception pkcs1e) {
	    throw new SignatureException("encoding error.");
	}

	// c) Convert the signature representative s to a signature S of length
	// k octets:
	// S = I2OSP (s, k)
	// 3) Output the signature S.
	try {
	    return PKCS1Operations.I2OSP(s, (modBits + 7) >> 3);
	} catch (PKCS1Exception pkcs1e) {
	    throw new SignatureException("internal error.");
	}
    }

    /**
     * Verifies a signature.
     * 
     * @param signature
     *                the signature to be verified
     * @return true if the signature is correct, false otherwise.
     */
    public boolean verify(byte[] signature) {
	FlexiBigInt m, s;
	byte[] EM;

	// 1) Length checking: If the length of the signature S is not k octets,
	// output "invalid signature" and stop.
	if (signature.length != cipherBlockSize) {
	    return false;
	}

	// 2) MeRSA verification:
	// a) Convert the signature S to an integer signature representative s:
	s = PKCS1Operations.OS2IP(signature);

	try {
	    // b) Apply the MeRSAVP1 (equivalent to MeRSAEP) verification
	    // primitive to the MeRSA public key (n, e) and the signature
	    // representative s to produce an integer message representative m =
	    // MeRSAVP1 ((n, e), s).
	    // *) If MeRSAVP1 outputs "signature representative out of range",
	    // output "invalid signature" and stop.
	    m = MeRSAOperations.MeRSAEP(pubKey, s);
	    // Convert the message representative m to an encoded message EM of
	    // length emLen = ceil((modBits-1)/8) octets, where modBits is the
	    // length in bits of the MeRSA modulus n: EM = I2OSP (m, emLen)
	    // Note that emLen will be one less than k if modBits-1 is divisible
	    // by 8 and equal to k otherwise.
	    // **) If I2OSP outputs "integer too large", output "invalid
	    // signature" and stop.
	    int emLen = (modBits - 1 + 7) >> 3;
	    EM = PKCS1Operations.I2OSP(m, emLen);
	} catch (PKCS1Exception pkcs1e) {
	    // *) MeRSAEP throws PKCS1Execption if signature representative out
	    // of range.
	    // **) I2OSP throws PKCS1Exception in case octet representation of m
	    // is longer than emLen.
	    return false;
	}

	// 3) EMSA-PSS verification: Apply the EMSA-PSS verification operation
	// to the message M and the encoded message EM to determine whether they
	// are consistent: Result = EMSA-PSS-VERIFY (M, EM, modBits-1)
	// 4) If Result = "consistent", output "valid signature". Otherwise,
	// output "invalid signature".
	try {
	    return PKCS1Operations.EMSA_PSS_VERIFY(getMessage(), EM,
		    modBits - 1, md);
	} catch (IOException ioe) {
	    throw new RuntimeException(ioe.getMessage());
	}
    }

}
