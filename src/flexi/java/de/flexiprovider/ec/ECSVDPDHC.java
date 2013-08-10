/*
 * Copyright (c) 1998-2008 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */
package de.flexiprovider.ec;

import de.flexiprovider.api.KeyAgreement;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.exceptions.NoSuchAlgorithmException;
import de.flexiprovider.api.exceptions.ShortBufferException;
import de.flexiprovider.api.keys.Key;
import de.flexiprovider.api.keys.PrivateKey;
import de.flexiprovider.api.keys.PublicKey;
import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.exceptions.InvalidPointException;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.math.ellipticcurves.Point;
import de.flexiprovider.common.math.ellipticcurves.ScalarMult;
import de.flexiprovider.ec.keys.ECPrivateKey;
import de.flexiprovider.ec.keys.ECPublicKey;
import de.flexiprovider.ec.keys.ECSecretKey;

/**
 * <tt>ECSVDPDHC</tt> provides the implementation for key exchange with the
 * Diffie Hellman algorithm on elliptic curves <tt>GP(p)</tt>, where
 * <tt>p</tt> is an odd prime number.
 * <p>
 * This class implements the ECSVDP-DHC primitive from IEEE 1363, i.e. the
 * Diffie Hellman algorithm with co-factor multiplication.
 * <p>
 * Usage:
 * <p>
 * <tt>kagA</tt> and <tt>kagB</tt> represent the parties trying to establish
 * a shared secret key, each with a private and public key. The following steps
 * have to be performed:
 * 
 * <pre>
 * KeyAgreement kagA = KeyAgreement.getInstance(&quot;ECDH&quot;, &quot;FlexiEC&quot;);
 * kagA.init(ecprivA, params, random);
 * KeyAgreement kagB = KeyAgreement.getInstance(&quot;ECDH&quot;, &quot;FlexiEC&quot;);
 * kagB.init(ecprivB, random);
 * ECSecretKey secrA = (ECSecretKey) kagA.doPhase(ecpubB, true);
 * ECSecretKey secrB = (ECSecretKey) kagB.doPhase(ecpubA, true);
 * </pre>
 * 
 * @author Jochen Hechler
 * @author Marcus St&ouml;gbauer
 * @author Martin Döring
 * 
 * @see ECPrivateKey
 * @see ECPublicKey
 * @see ECSecretKey
 */
public class ECSVDPDHC extends KeyAgreement {

    // the private key value
    private FlexiBigInt mS;

    // the public key
    private ECPublicKey mOtherKey;

    /**
     * flag indicating whether cofactor multiplication shall be used
     */
    protected boolean withCoFactor = true;

    // the (optional) cofactor
    private FlexiBigInt mK;

    /**
     * Initializes this <tt>ECSVDPDHC</tt> with a key, the curve parameters
     * and some random information which is not being used here.
     * 
     * @param key
     *                is the private key of the party initializing ECSVDPDHC
     * @param params
     *                are the curve parameters
     * @param random
     *                contains some random information that are randomly ignored
     * @throws InvalidKeyException
     *                 if <tt>key</tt> is no instance of {@link ECPrivateKey}.
     */
    public void init(PrivateKey key, AlgorithmParameterSpec params,
	    SecureRandom random) throws InvalidKeyException {
	if (!(key instanceof ECPrivateKey)) {
	    throw new InvalidKeyException("unsupported type");
	}
	ECPrivateKey ecPrivKey = (ECPrivateKey) key;

	mS = ecPrivKey.getS();
	mK = FlexiBigInt.valueOf(ecPrivKey.getParams().getK());
    }

    /**
     * Initializes this <tt>ECSVDPDHC</tt> with a key and some random
     * information which is not being used here.
     * 
     * @param key
     *                is the secret key of the party initializing ECSVDPDHC
     * @param random
     *                contains some random information that are randomly ignored
     * 
     * @throws InvalidKeyException
     *                 if <tt>key</tt> is no instance of <tt>
     * ECPrivateKey</tt>
     * 
     */
    public void init(PrivateKey key, SecureRandom random)
	    throws InvalidKeyException {
	if (!(key instanceof ECPrivateKey)) {
	    throw new InvalidKeyException("unsupported type");
	}
	ECPrivateKey ecPrivKey = (ECPrivateKey) key;

	mS = ecPrivKey.getS();
	mK = FlexiBigInt.valueOf(ecPrivKey.getParams().getK());
    }

    /**
     * Generate the shared secret via the algorithm specified in
     * <tt>algorithm</tt>. Only <tt>ECDH</tt> is valid for algorithm. This
     * is only a wrapper function, the whole work is done in
     * <tt>secretGenerator</tt>.
     * 
     * @param algorithm
     *                is the desired algorithm for the generation of the secret
     * @return the shared secret as an {@link SecretKey}
     * @throws NoSuchAlgorithmException
     *                 if <tt>algorithm</tt> isn't <tt>ECDH</tt>
     */
    public SecretKey generateSecret(String algorithm)
	    throws NoSuchAlgorithmException {
	SecretKey secr = null;
	if (!(algorithm.equals("ECDH"))) {
	    throw new NoSuchAlgorithmException(algorithm + " is not supported");
	}

	try {
	    secr = secretGenerator();
	} catch (InvalidKeyException ex) {
	    throw new RuntimeException("Can't generate shared secret: "
		    + ex.getMessage());
	}

	return secr;
    }

    /**
     * Generates the shared secret, and places it into the buffer sharedSecret,
     * beginning at offset inclusive.
     * 
     * This is only a wrapper function, the whole work is done in
     * <tt>secretGenerator</tt>.
     * 
     * @param sharedSecret
     *                is the buffer for the shared secret
     * @param offset
     *                is the offset in <tt>sharedSecret</tt> where the shared
     *                secret will be stored
     * @return the number of bytes written in <tt>sharedSecret</tt>
     * @throws ShortBufferException
     *                 if <tt>sharedSecret</tt> is too small to to hold the
     *                 shared secret
     */
    public int generateSecret(byte[] sharedSecret, int offset)
	    throws ShortBufferException {
	ECSecretKey secr = null;
	try {
	    secr = secretGenerator();
	} catch (InvalidKeyException ex) {
	    throw new RuntimeException("Can't generate shared secret: "
		    + ex.getMessage());
	}
	byte[] sByte = secr.getS().toByteArray();
	int n = sByte.length;
	try {
	    System.arraycopy(sByte, 0, sharedSecret, offset, n);
	} catch (IndexOutOfBoundsException ex) {
	    throw new ShortBufferException(
		    "Byte array sharedSecret too small for shared secret.");
	}

	return n;
    }

    /**
     * Generates the shared Secret and returns it as an byte-array.
     * 
     * This is only a wrapper function, the whole work is done in
     * <tt>secretGenerator</tt>.
     * 
     * @return the shared SecretValue as an byte-array, and null if the object
     *         is not in DoPhase
     */
    public byte[] generateSecret() {
	ECSecretKey secr = null;

	try {
	    secr = secretGenerator();
	} catch (InvalidKeyException ex) {
	    throw new RuntimeException("Can't generate shared secret: "
		    + ex.getMessage());
	}

	return secr.getS().toByteArray();
    }

    /**
     * Executes the next phase of this key agreement with the given key that was
     * received from one of the other parties involved in this key agreement.
     * 
     * @param key
     *                the public key of the other party
     * @param lastPhase
     *                true, if this is the last phase of the key agreement.
     *                After the last phase only <tt>generateSecret</tt> should
     *                be called.
     * @return the shared secret as a <tt>java.security.Key</tt>
     * @throws InvalidKeyException
     *                 if <tt>key</tt> is no interface of an
     *                 <tt>ECPublicKey</tt> or if <tt>key</tt> is an invalid
     *                 <tt>ECPublicKey</tt>
     */
    public Key doPhase(PublicKey key, boolean lastPhase)
	    throws InvalidKeyException {

	if (!(key instanceof ECPublicKey)) {
	    throw new InvalidKeyException("unsupported type");
	}
	mOtherKey = (ECPublicKey) key;

	if (!ECTools.isValidPublicKey(mOtherKey)) {
	    throw new InvalidKeyException("invalid key");
	}
	try {
	    if (lastPhase) {
		return generateSecret("ECDH");
	    }
	    return null;
	} catch (NoSuchAlgorithmException ex) {
	    // the requested type is correct
	    throw new RuntimeException("internal error");
	}
    }

    /**
     * Generates the shared secret. This is done by multiplying the point Q from
     * the public key with the private key d and the co-factor k. The shared
     * secret is the x coordinate of the point after the multiplication.
     * 
     * @return the shared secret as an <tt>ECSecretKey</tt>
     * @throws InvalidKeyException
     *                 if <tt>mOtherKey</tt> has not been initialized with EC
     *                 domain parameters yet.
     */
    private ECSecretKey secretGenerator() throws InvalidKeyException {
	// obtain the public key value
	Point q = mOtherKey.getW();

	// scalar multiplication with private key value
	q = ScalarMult.multiply(mS, q);

	// optional cofactor multiplication
	if (withCoFactor) {
	    q = ScalarMult.multiply(mK, q);
	}

	// verify that the result is not the point at infinity
	if (q.isZero()) {
	    throw new InvalidPointException("shared secret is invalid");
	}

	// return the x-coordinate of the computed point as EC secret key
	return new ECSecretKey(q.getXAffin().toFlexiBigInt());
    }

}
