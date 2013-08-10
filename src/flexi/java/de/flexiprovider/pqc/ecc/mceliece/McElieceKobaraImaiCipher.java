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
import de.flexiprovider.common.math.IntegerFunctions;
import de.flexiprovider.common.math.linearalgebra.GF2Vector;
import de.flexiprovider.common.util.ByteUtils;
import de.flexiprovider.pqc.ecc.Conversions;

/**
 * This class implements the Kobara/Imai conversion of the McEliecePKCS. This is
 * a conversion of the McEliecePKCS which is CCA2-secure. For details, see D.
 * Engelbert, R. Overbeck, A. Schmidt, "A summary of the development of the
 * McEliece Cryptosystem", technical report.
 * <p>
 * This class extends the <a href="javax.crypto.CipherSpi">CipherSpi</a> class.
 * <p>
 * The Kobara/Imai conversion can be used as follows:
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
 * Cipher cipher = Cipher.getInstance(&quot;McElieceKobaraImaiConversion&quot;);
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
public class McElieceKobaraImaiCipher extends AsymmetricHybridCipher {

    /**
     * The OID of the algorithm.
     */
    public static final String OID = McElieceCCA2KeyFactory.OID + ".3";

    private static final String DEFAULT_PRNG_NAME = "SHA1PRNG";

    /**
     * A predetermined public constant.
     */
    public static final byte[] PUBLIC_CONSTANT = "a predetermined public constant"
	    .getBytes();

    private McElieceCCA2PublicKey pubKey;

    private McElieceCCA2PrivateKey privKey;

    private MessageDigest md;

    private SecureRandom sr;

    private String mdName;

    private String prngName;

    private int helpLen;

    /**
     * The McEliece main parameters
     */
    private int n, k, t;

    /**
     * buffer to store the input data
     */
    private ByteArrayOutputStream buf = new ByteArrayOutputStream();

    public McElieceKobaraImaiCipher() {
	buf = new ByteArrayOutputStream();
    }

    /**
     * @return the name of this cipher
     */
    public String getName() {
	return "McElieceKobaraImaiCipher";
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
	throw new InvalidKeyException("unsupported type");
    }

    protected int decryptOutputSize(int inLen) {
	// TODO return correct output size
	return 0;
    }

    protected int encryptOutputSize(int inLen) {
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
     *                 if this cipher is in decryption mode, and (un)padding has
     *                 been requested, but the decrypted data is not bounded by
     *                 the appropriate padding bytes
     */
    public byte[] doFinal(byte[] input, int inOff, int inLen)
	    throws BadPaddingException {
	update(input, inOff, inLen);
	if (opMode == ENCRYPT_MODE) {
	    return messageEncrypt();
	} else if (opMode == DECRYPT_MODE) {
	    return messageDecrypt();
	}
	return null;
    }

    protected void initCipherEncrypt(Key key, AlgorithmParameterSpec params,
	    SecureRandom sr) throws InvalidKeyException,
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

	helpLen = (IntegerFunctions.binomial(n, t).bitLength() - 1) >> 3;
	helpLen += (k >> 3) - md.getDigestLength() - PUBLIC_CONSTANT.length;

	buf = new ByteArrayOutputStream();
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
	k = privKey.getK();
	t = privKey.getT();

	buf = new ByteArrayOutputStream();
    }

    protected byte[] messageEncrypt() {

	int c2Len = md.getDigestLength();
	int c4Len = k >> 3;
	int c5Len = (IntegerFunctions.binomial(n, t).bitLength() - 1) >> 3;

	// compute message representative
	byte[] input = pad();

	int mLen = c4Len + c5Len - c2Len - PUBLIC_CONSTANT.length;
	if (input.length > mLen) {
	    mLen = input.length;
	}

	int c1Len = mLen + PUBLIC_CONSTANT.length;
	int c6Len = c1Len + c2Len - c4Len - c5Len;

	// compute (m||const)
	byte[] mConst = new byte[c1Len];
	System.arraycopy(input, 0, mConst, 0, input.length);
	System.arraycopy(PUBLIC_CONSTANT, 0, mConst, mLen,
		PUBLIC_CONSTANT.length);

	// generate random r of length c2Len bytes
	byte[] r = new byte[c2Len];
	sr.nextBytes(r);

	// get PRNG object
	SecureRandom sr0 = null;
	try {
	    sr0 = Registry.getSecureRandom(prngName);
	} catch (NoSuchAlgorithmException nsae) {
	    throw new RuntimeException("Secure random '" + prngName
		    + "' not found.");
	}

	// seed PRNG with r
	sr0.setSeed(r);

	// generate random sequence ...
	byte[] c1 = new byte[c1Len];
	sr0.nextBytes(c1);

	// ... and XOR with (m||const) to obtain c1
	for (int i = c1Len - 1; i >= 0; i--) {
	    c1[i] ^= mConst[i];
	}

	// compute H(c1) ...
	byte[] c2 = md.digest(c1);

	// ... and XOR with r
	for (int i = c2Len - 1; i >= 0; i--) {
	    c2[i] ^= r[i];
	}

	// compute (c2||c1)
	byte[] c2c1 = ByteUtils.concatenate(c2, c1);

	// split (c2||c1) into (c6||c5||c4), where c4Len is k/8 bytes, c5Len is
	// floor[log(n|t)]/8 bytes, and c6Len is c1Len+c2Len-c4Len-c5Len (may be
	// 0).
	byte[] c6 = new byte[0];
	if (c6Len > 0) {
	    c6 = new byte[c6Len];
	    System.arraycopy(c2c1, 0, c6, 0, c6Len);
	}

	byte[] c5 = new byte[c5Len];
	System.arraycopy(c2c1, c6Len, c5, 0, c5Len);

	byte[] c4 = new byte[c4Len];
	System.arraycopy(c2c1, c6Len + c5Len, c4, 0, c4Len);

	// convert c4 to vector over GF(2)
	GF2Vector c4Vec = GF2Vector.OS2VP(k, c4);

	// convert c5 to error vector z
	GF2Vector z = Conversions.encode(n, t, c5);

	// compute encC4 = E(c4, z)
	byte[] encC4 = McElieceCCA2Primitives.encryptionPrimitive(pubKey,
		c4Vec, z).getEncoded();

	// if c6Len > 0
	if (c6Len > 0) {
	    // return (c6||encC4)
	    return ByteUtils.concatenate(c6, encC4);
	}
	// else, return encC4
	return encC4;
    }

    /**
     * Pad and return the message stored in the message buffer.
     * 
     * @return the padded message
     */
    private byte[] pad() {
	buf.write(0x01);
	byte[] result = buf.toByteArray();
	buf.reset();
	return result;
    }

    protected byte[] messageDecrypt() throws BadPaddingException {

	byte[] input = buf.toByteArray();
	buf.reset();

	int nDiv8 = n >> 3;

	if (input.length < nDiv8) {
	    throw new BadPaddingException("Ciphertext too short.");
	}

	int c2Len = md.getDigestLength();
	int c4Len = k >> 3;
	int c6Len = input.length - nDiv8;

	// split ciphertext (c6||encC4), where c6 may be empty
	byte[] c6, encC4;
	if (c6Len > 0) {
	    byte[][] c6EncC4 = ByteUtils.split(input, c6Len);
	    c6 = c6EncC4[0];
	    encC4 = c6EncC4[1];
	} else {
	    c6 = new byte[0];
	    encC4 = input;
	}

	// convert encC4 into vector over GF(2)
	GF2Vector encC4Vec = GF2Vector.OS2VP(n, encC4);

	// decrypt encC4Vec to obtain c4 and error vector z
	GF2Vector[] c4z = McElieceCCA2Primitives.decryptionPrimitive(privKey,
		encC4Vec);
	byte[] c4 = c4z[0].getEncoded();
	GF2Vector z = c4z[1];

	// if length of c4 is greater than c4Len (because of padding) ...
	if (c4.length > c4Len) {
	    // ... truncate the padding bytes
	    c4 = ByteUtils.subArray(c4, 0, c4Len);
	}

	// compute c5 = Conv^-1(z)
	byte[] c5 = Conversions.decode(n, t, z);

	// compute (c6||c5||c4)
	byte[] c6c5c4 = ByteUtils.concatenate(c6, c5);
	c6c5c4 = ByteUtils.concatenate(c6c5c4, c4);

	// split (c6||c5||c4) into (c2||c1), where c2Len = mdLen and c1Len =
	// input.length-c2Len bytes.
	int c1Len = c6c5c4.length - c2Len;
	byte[][] c2c1 = ByteUtils.split(c6c5c4, c2Len);
	byte[] c2 = c2c1[0];
	byte[] c1 = c2c1[1];

	// compute H(c1) ...
	byte[] rPrime = md.digest(c1);

	// ... and XOR with c2 to obtain r'
	for (int i = c2Len - 1; i >= 0; i--) {
	    rPrime[i] ^= c2[i];
	}

	// get PRNG object
	SecureRandom sr0 = null;
	try {
	    sr0 = Registry.getSecureRandom(prngName);
	} catch (NoSuchAlgorithmException nsae) {
	    throw new RuntimeException("Secure random '" + prngName
		    + "' not found.");
	}

	// seed PRNG with r'
	sr0.setSeed(rPrime);

	// generate random sequence R(r') ...
	byte[] mConstPrime = new byte[c1Len];
	sr0.nextBytes(mConstPrime);

	// ... and XOR with c1 to obtain (m||const')
	for (int i = c1Len - 1; i >= 0; i--) {
	    mConstPrime[i] ^= c1[i];
	}

	if (mConstPrime.length < c1Len) {
	    throw new BadPaddingException("invalid ciphertext");
	}

	byte[][] temp = ByteUtils.split(mConstPrime, c1Len
		- PUBLIC_CONSTANT.length);
	byte[] mr = temp[0];
	byte[] constPrime = temp[1];

	if (!ByteUtils.equals(constPrime, PUBLIC_CONSTANT)) {
	    throw new BadPaddingException("invalid ciphertext");
	}

	// extract and return plaintext
	return unpad(mr);
    }

    /**
     * Unpad a message.
     * 
     * @param pmBytes
     *                the padded message
     * @return the message
     * @throws BadPaddingException
     *                 if the padded message is invalid.
     */
    private byte[] unpad(byte[] pmBytes) throws BadPaddingException {
	// find first non-zero byte
	int index;
	for (index = pmBytes.length - 1; index >= 0 && pmBytes[index] == 0; index--)
	    ;

	// check if padding byte is valid
	if (pmBytes[index] != 0x01) {
	    throw new BadPaddingException("invalid ciphertext");
	}

	// extract and return message
	byte[] mBytes = new byte[index];
	System.arraycopy(pmBytes, 0, mBytes, 0, index);
	return mBytes;
    }

    private void reset() {
	privKey = null;
	pubKey = null;
	md = null;
	sr = null;
	n = 0;
	k = 0;
	t = 0;
	buf.reset();
    }

}
