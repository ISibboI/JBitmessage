/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.rsa;

import de.flexiprovider.api.AsymmetricBlockCipher;
import de.flexiprovider.api.MessageDigest;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.Signature;
import de.flexiprovider.api.exceptions.BadPaddingException;
import de.flexiprovider.api.exceptions.IllegalBlockSizeException;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.exceptions.SignatureException;
import de.flexiprovider.api.keys.PrivateKey;
import de.flexiprovider.api.keys.PublicKey;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.core.md.MD5;
import de.flexiprovider.core.md.SHA1;

/**
 * This class implements the RSA signature algorithm as defined in <a
 * href="http://">SSL</a>. Note that this is a special version of a RSA
 * signature that does not use a PKCS#1-compliant DigestInfo structure!
 */
public class SSLSignature extends Signature {

    /**
     * The source of randomness.
     */
    private SecureRandom secureRandom_;

    /**
     * The fist message digest: MD5.
     */
    private MessageDigest mdMD5_;

    /**
     * The second message digest: SHA1.
     */
    private MessageDigest mdSHA1_;

    /**
     * The cipher algorithm - here RSA.
     */
    private AsymmetricBlockCipher cipher_;

    private void initCommon() {
	mdSHA1_ = new SHA1();
	mdMD5_ = new MD5();
	cipher_ = new RSA_PKCS1_v1_5();
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
	secureRandom_ = secureRandom;
	cipher_.initEncrypt(privateKey, secureRandom_);
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
	initCommon();
	cipher_.initDecrypt(publicKey);
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
     * Passes message bytes to the message digest.
     * 
     * @param b
     *                The message byte.
     * @param offset
     *                The index, where the message bytes starts.
     * @param length
     *                The number of message bytes.
     */
    public void update(byte[] b, int offset, int length) {
	mdMD5_.update(b, offset, length);
	mdSHA1_.update(b, offset, length);
    }

    /**
     * Passes a message byte to the message digest.
     * 
     * @param b
     *                the message byte.
     */
    public void update(byte b) {
	mdMD5_.update(b);
	mdSHA1_.update(b);
    }

    /**
     * Signs a message.
     * 
     * @return the signature.
     * @throws SignatureException
     *                 if the signature is not initialized properly.
     */
    public byte[] sign() throws SignatureException {

	byte[] out = null;
	byte[] shaMBytes = mdSHA1_.digest();
	byte[] mdMBytes = mdMD5_.digest();
	byte[] plainSig = new byte[16 + 20];

	// System.out.println("sha " + (new String(shaMBytes)));
	System.arraycopy(mdMBytes, 0, plainSig, 0, 16);
	System.arraycopy(shaMBytes, 0, plainSig, 16, 20);

	try {
	    out = cipher_.doFinal(plainSig);
	    return out;
	} catch (IllegalBlockSizeException ibse) {
	    throw new SignatureException(
		    "SSLSignature: failure in cipher.doFinal() (illegal block size)");
	} catch (BadPaddingException bpe) {
	    throw new SignatureException(
		    "SSLSignature: failure in cipher.doFinal() (bad padding)");
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

	byte[] shaMBytes = mdSHA1_.digest();
	byte[] mdMBytes = mdMD5_.digest();
	byte[] plain;

	try {
	    plain = cipher_.doFinal(signature);

	    for (int i = 0; i < 16; i++) {
		if (plain[i] != mdMBytes[i]) {
		    return false;
		}
		if (plain[16 + i] != shaMBytes[i]) {
		    return false;
		}
	    }
	    for (int i = 0; i < 4; i++) {
		if (plain[16 + 16 + i] != shaMBytes[16 + i]) {
		    return false;
		}
	    }

	    return true;

	} catch (IllegalBlockSizeException ibse) {
	    System.err.println("RSASignature: cipher.doFinal");
	    ibse.printStackTrace();
	} catch (BadPaddingException bpe) {
	    System.err.println("RSASignature: cipher.doFinal");
	    bpe.printStackTrace();
	}

	return false;
    }

}
