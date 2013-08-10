package de.flexiprovider.pqc.ecc.mceliece;

import java.io.ByteArrayOutputStream;

import de.flexiprovider.api.AsymmetricHybridCipher;
import de.flexiprovider.api.MessageDigest;
import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.exceptions.BadPaddingException;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.exceptions.NoSuchAlgorithmException;
import de.flexiprovider.api.keys.Key;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.math.linearalgebra.GF2Vector;
import de.flexiprovider.common.util.ByteUtils;
import de.flexiprovider.pqc.ecc.Conversions;

/**
 * This class implements the Fujisaki/Okamoto conversion of the McEliecePKCS.
 * Fujisaki and Okamoto propose hybrid encryption that merges a symmetric
 * encryption scheme which is secure in the find-guess model with an asymmetric
 * one-way encryption scheme which is sufficiently probabilistic to obtain a
 * public key cryptosystem which is CCA2-secure. For details, see D. Engelbert,
 * R. Overbeck, A. Schmidt, "A summary of the development of the McEliece
 * Cryptosystem", technical report.
 * <p>
 * This class extends the <a href="javax.crypto.CipherSpi">CipherSpi</a> class.
 * <p>
 * The Fujisaki/Okamoto conversion can be used as follows:
 * <p>
 * To encrypt a message, the following steps have to be performed:
 * 
 * <pre>
 * // setup
 * KeyPairGenerator kpg = KeyPairGenerator.getInstance(&quot;McEliece&quot;, &quot;FlexiPQC&quot;);
 * KeyPair keys = kpg.generateKeyPair();
 * McElieceCCA2PublicKey pubK = (McElieceCCA2PublicKey) keys.getPublic();
 * McElieceCCA2PrivateKey privK = (McElieceCCA2PrivateKey) keys.getPrivate();
 * SecureRandom sr = Registry.getSecureRandom();
 * Cipher cipher = Cipher.getInstance(&quot;McElieceFujisakiConversion&quot;);
 * 
 * // the string to encrypt and decrypt
 * String m = &quot;This is a test for the Fujisaki conversion of the McEliecePKCS.&quot;;
 * byte[] mBytes = m.getBytes();
 * 
 * // initialize cipher in encrypt mode
 * cipher.init(Cipher.ENCRYPT_MODE, pubK, sr);
 * 
 * // encrypt
 * byte[] cBytes = cipher.doFinal(mBytes);
 * </pre>
 * 
 * To decrypt, the following steps have to be performed (using setup from
 * above):
 * 
 * <pre>
 * // initialize cipher in decrypt mode
 * cipher.init(Cipher.DECRYPT_MODE, privK);
 * 
 * // decrypt
 * byte[] decBytes = cipher.doFinal(cBytes);
 * String newM = new String(decBytes);
 * </pre>
 */
public class McElieceFujisakiCipher extends AsymmetricHybridCipher {

    /**
     * The OID of the algorithm.
     */
    public static final String OID = McElieceCCA2KeyFactory.OID + ".1";

    private static final String DEFAULT_PRNG_NAME = "SHA1PRNG";

    private McElieceCCA2PublicKey pubKey;

    private McElieceCCA2PrivateKey privKey;

    private String mdName;

    private String prngName;

    private MessageDigest md;

    private SecureRandom sr;

    /**
     * The McEliece main parameters
     */
    private int n, k, t;

    /**
     * buffer to store the input data
     */
    private ByteArrayOutputStream buf = new ByteArrayOutputStream();

    /**
     * @return the name of this cipher
     */
    public String getName() {
	return "McElieceFujisakiCipher";
    }

    /**
     * Return the key size of the given key object. Checks whether the key
     * object is an instance of <tt>McElieceCCA2PublicKey</tt> or
     * <tt>McElieceCCA2PrivateKey</tt>.
     * 
     * @param key
     *                the key object
     * @return the keysize of the given key object
     * @throws InvalidKeyException
     *                 if the key is invalid
     */
    public int getKeySize(Key key) throws InvalidKeyException {
	if (key instanceof McElieceCCA2PrivateKey) {
	    return ((McElieceCCA2PrivateKey) key).getN();
	}
	if (key instanceof McElieceCCA2PublicKey) {
	    return ((McElieceCCA2PublicKey) key).getN();
	}
	throw new InvalidKeyException("Unsupported key.");
    }

    protected int encryptOutputSize(int inLen) {
	// TODO return correct output size
	return 0;
    }

    protected int decryptOutputSize(int inLen) {
	// TODO return correct output size
	return 0;
    }

    /**
     * Continue a multiple-part encryption or decryption operation.
     * 
     * @param input
     *                byte array containing the next part of the input
     * @param inOff
     *                index in the array where the input starts
     * @param inLen
     *                length of the input
     * @return the processed byte array.
     */
    public byte[] update(byte[] input, int inOff, int inLen) {
	buf.write(input, inOff, inLen);
	return new byte[0];
    }

    /**
     * Encrypts or decrypts data in a single-part operation, or finishes a
     * multiple-part operation. The data is encrypted or decrypted, depending on
     * how this cipher was initialized.
     * 
     * @param input
     *                the input buffer
     * @param inOff
     *                the offset in input where the input starts
     * @param inLen
     *                the input length
     * @return the new buffer with the result
     * @throws BadPaddingException
     *                 on decryption errors.
     */
    public byte[] doFinal(byte[] input, int inOff, int inLen)
	    throws BadPaddingException {
	update(input, inOff, inLen);
	byte[] data = buf.toByteArray();
	buf.reset();
	if (opMode == ENCRYPT_MODE) {
	    return messageEncrypt(data);
	} else if (opMode == DECRYPT_MODE) {
	    return messageDecrypt(data);
	}
	return null;
    }

    protected void initCipherEncrypt(Key key, AlgorithmParameterSpec params,
	    SecureRandom secureRand) throws InvalidKeyException,
	    InvalidAlgorithmParameterException {

	if (!(key instanceof McElieceCCA2PublicKey)) {
	    reset();
	    throw new InvalidKeyException("unsupported type");
	}
	pubKey = (McElieceCCA2PublicKey) key;

	// if no parameters are given
	if (params == null) {
	    // generate the default parameters
	    params = new McElieceCCA2ParameterSpec();
	}

	if (!(params instanceof McElieceCCA2ParameterSpec)) {
	    throw new InvalidAlgorithmParameterException("unsupported type");
	}

	mdName = ((McElieceCCA2ParameterSpec) params).getMDName();
	prngName = DEFAULT_PRNG_NAME;

	try {
	    md = Registry.getMessageDigest(mdName);
	} catch (NoSuchAlgorithmException nsae) {
	    // the McElieceCCA2ParameterSpec constructor checks whether the
	    // message digest is available. So if it is not available here, this
	    // is an internal error.
	    throw new RuntimeException("internal error");
	}

	this.sr = sr != null ? sr : Registry.getSecureRandom();

	n = pubKey.getN();
	k = pubKey.getK();
	t = pubKey.getT();
    }

    protected void initCipherDecrypt(Key key, AlgorithmParameterSpec params)
	    throws InvalidKeyException, InvalidAlgorithmParameterException {

	if (!(key instanceof McElieceCCA2PrivateKey)) {
	    reset();
	    throw new InvalidKeyException("unsupported type");
	}
	privKey = (McElieceCCA2PrivateKey) key;

	// if no parameters are given
	if (params == null) {
	    // generate the default parameters
	    params = new McElieceCCA2ParameterSpec();
	}

	if (!(params instanceof McElieceCCA2ParameterSpec)) {
	    throw new InvalidAlgorithmParameterException("unsupported type");
	}

	mdName = ((McElieceCCA2ParameterSpec) params).getMDName();
	prngName = DEFAULT_PRNG_NAME;

	try {
	    md = Registry.getMessageDigest(mdName);
	} catch (NoSuchAlgorithmException nsae) {
	    // the McElieceCCA2ParameterSpec constructor checks whether the
	    // message digest is available. So if it is not available here, this
	    // is an internal error.
	    throw new RuntimeException("internal error");
	}

	n = privKey.getN();
	t = privKey.getT();
    }

    protected byte[] messageEncrypt(byte[] input) {

	// generate random vector r of length k bits
	GF2Vector r = new GF2Vector(k, sr);

	// convert r to byte array
	byte[] rBytes = r.getEncoded();

	// compute (r||input)
	byte[] rm = ByteUtils.concatenate(rBytes, input);

	// compute H(r||input)
	md.update(rm);
	byte[] hrm = md.digest();

	// convert H(r||input) to error vector z
	GF2Vector z = Conversions.encode(n, t, hrm);

	// compute c1 = E(r, z)
	byte[] c1 = McElieceCCA2Primitives.encryptionPrimitive(pubKey, r, z)
		.getEncoded();

	// get PRNG object
	SecureRandom sr0 = null;
	try {
	    sr0 = Registry.getSecureRandom(prngName);
	} catch (NoSuchAlgorithmException nsae) {
	    throw new RuntimeException("Secure random '" + prngName
		    + "' not found.");
	}

	// seed PRNG with r
	sr0.setSeed(rBytes);

	// generate random c2
	byte[] c2 = new byte[input.length];
	sr0.nextBytes(c2);

	// XOR with input
	for (int i = 0; i < input.length; i++) {
	    c2[i] ^= input[i];
	}

	// return (c1||c2)
	return ByteUtils.concatenate(c1, c2);
    }

    protected byte[] messageDecrypt(byte[] input) throws BadPaddingException {

	int c1Len = (n + 7) >> 3;
	int c2Len = input.length - c1Len;

	// split ciphertext (c1||c2)
	byte[][] c1c2 = ByteUtils.split(input, c1Len);
	byte[] c1 = c1c2[0];
	byte[] c2 = c1c2[1];

	// decrypt c1 ...
	GF2Vector hrmVec = GF2Vector.OS2VP(n, c1);
	GF2Vector[] decC1 = McElieceCCA2Primitives.decryptionPrimitive(privKey,
		hrmVec);
	byte[] rBytes = decC1[0].getEncoded();
	// ... and obtain error vector z
	GF2Vector z = decC1[1];

	// get PRNG object
	SecureRandom sr0 = null;
	try {
	    sr0 = Registry.getSecureRandom(prngName);
	} catch (NoSuchAlgorithmException nsae) {
	    throw new RuntimeException("Secure random '" + prngName
		    + "' not found.");
	}

	// seed PRNG with r
	sr0.setSeed(rBytes);

	// generate random sequence
	byte[] mBytes = new byte[c2Len];
	sr0.nextBytes(mBytes);

	// XOR with c2 to obtain m
	for (int i = 0; i < c2Len; i++) {
	    mBytes[i] ^= c2[i];
	}

	// compute H(r||m)
	byte[] rmBytes = ByteUtils.concatenate(rBytes, mBytes);
	byte[] hrm = md.digest(rmBytes);

	// compute Conv(H(r||m))
	hrmVec = Conversions.encode(n, t, hrm);

	// check that Conv(H(m||r)) = z
	if (!hrmVec.equals(z)) {
	    throw new BadPaddingException("invalid ciphertext");
	}

	// return plaintext m
	return mBytes;
    }

    private void reset() {
	privKey = null;
	pubKey = null;
	sr = null;
	buf.reset();
    }

}
