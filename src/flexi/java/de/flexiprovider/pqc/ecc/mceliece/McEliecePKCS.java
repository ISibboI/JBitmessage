package de.flexiprovider.pqc.ecc.mceliece;

import java.io.ByteArrayOutputStream;

import de.flexiprovider.api.AsymmetricBlockCipher;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.exceptions.BadPaddingException;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.keys.Key;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.math.codingtheory.GF2mField;
import de.flexiprovider.common.math.codingtheory.GoppaCode;
import de.flexiprovider.common.math.codingtheory.PolynomialGF2mSmallM;
import de.flexiprovider.common.math.linearalgebra.GF2Matrix;
import de.flexiprovider.common.math.linearalgebra.GF2Vector;
import de.flexiprovider.common.math.linearalgebra.Permutation;
import de.flexiprovider.common.math.linearalgebra.Vector;

/**
 * This class implements the McEliece Public Key cryptosystem (McEliecePKCS). It
 * was first described in R.J. McEliece, "A public key cryptosystem based on
 * algebraic coding theory", DSN progress report, 42-44:114-116, 1978. The
 * McEliecePKCS is the first cryptosystem which is based on error correcting
 * codes. The trapdoor for the McEliece cryptosystem using Goppa codes is the
 * knowledge of the Goppa polynomial used to generate the code.
 * <p>
 * The class extends the {@link AsymmetricBlockCipher} class.
 * <p>
 * The McEliecePKC can be used as follows:
 * <p>
 * To encrypt a message, the following steps have to be performed:
 * 
 * <pre>
 * // The message which should be encrypted
 * String message = &quot;secret message&quot;;
 * byte[] messageBytes = message.getBytes();
 * 
 * // Generate KeySpec from encoded McEliece public key:
 * KeySpec publicKeySpec = new X509EncodedKeySpec(encPublicKey);
 * 
 * // Initialize the McEliece key factory:&lt;br/&gt;
 * KeyFactory keyFactory = KeyFactory.getInstance(&quot;McEliece&quot;, &quot;FlexiPQC&quot;);
 * 
 * // Decode McEliece public key:&lt;br/&gt;
 * PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
 * 
 * // The source of randomness
 * SecureRandom secureRand = Registry.getSecureRandom();
 * 
 * // Obtain a McEliecePKC Cipher Object
 * Cipher cipher = Cipher.getInstance(&quot;McEliecePKCS&quot;);
 * 
 * // Initialize the cipher
 * cipher.init(Cipher.ENCRYPT_MODE, publicKey, secureRand);
 * 
 * // Finally encrypt the message
 * byte[] ciphertextBytes = cipher.doFinal(messageBytes);
 * </pre>
 * 
 * To decrypt a ciphertext, the following steps have to be performed:
 * 
 * <pre>
 * // Generate KeySpec from encoded McEliece private key:
 * KeySpec publicKeySpec = new PKCS8EncodedKeySpec(encPrivateKey);
 * 
 * // Initialize the McEliece key factory:&lt;br/&gt;
 * KeyFactory keyFactory = KeyFactory.getInstance(&quot;McEliece&quot;, &quot;FlexiPQC&quot;);
 * 
 * // Decode McEliece private key:&lt;br/&gt;
 * PublicKey privateKey = keyFactory.generatePrivate(privateKeySpec);
 * 
 * // Obtain a McEliecePKC Cipher Object
 * Cipher cipher = Cipher.getInstance(&quot;McEliecePKCS&quot;);
 * 
 * // Initialize the cipher
 * cipher.init(Cipher.DECRYPT_MODE, privateKey);
 * 
 * // Finally decrypt the message
 * byte[] messageBytes = cipher.doFinal(ciphertextBytes);
 * String message = new String(messageBytes);
 * </pre>
 * 
 * @see de.flexiprovider.api.AsymmetricBlockCipher
 * @author Elena Klintsevich
 */
public class McEliecePKCS extends AsymmetricBlockCipher {

    /**
     * The OID of the algorithm.
     */
    public static final String OID = McElieceKeyFactory.OID;

    // the public key
    private McEliecePublicKey pubKey;

    // the private key
    private McEliecePrivateKey privKey;

    // the source of randomness
    private SecureRandom sr;

    // the McEliece main parameters
    private int n, k, t;

    /**
     * @return the name of this cipher
     */
    public String getName() {
	return "McEliecePKCS";
    }

    /**
     * Return the key size of the given key object. Checks whether the key
     * object is an instance of <tt>McEliecePublicKey</tt> or
     * <tt>McEliecePrivateKey</tt>.
     * 
     * @param key
     *                the key object
     * @return the keysize of the given key object
     * @throws InvalidKeyException
     *                 if the key is invalid
     */
    public int getKeySize(Key key) throws InvalidKeyException {
	if (key instanceof McEliecePrivateKey) {
	    return ((McEliecePrivateKey) key).getN();
	}
	if (key instanceof McEliecePublicKey) {
	    return ((McEliecePublicKey) key).getN();
	}
	throw new InvalidKeyException("Unsupported key.");
    }

    /**
     * Initialize the block cipher with a public key for data encryption.
     * Currently, parameters are not supported.
     * 
     * @param key
     *                the key which shall be used to encrypt data
     * @param params
     *                the algorithm parameters
     * @param secureRandom
     *                the source of randomness
     * @throws InvalidKeyException
     *                 if the given key is inappropriate for initializing this
     *                 cipher.
     */
    protected void initCipherEncrypt(Key key, AlgorithmParameterSpec params,
	    SecureRandom secureRandom) throws InvalidKeyException {

	if (!(key instanceof McEliecePublicKey)) {
	    reset();
	    throw new InvalidKeyException("unsupported type");
	}
	pubKey = (McEliecePublicKey) key;

	sr = secureRandom;

	n = pubKey.getN();
	k = pubKey.getK();
	t = pubKey.getT();

	cipherTextSize = n >> 3;
	maxPlainTextSize = (k >> 3);
    }

    /**
     * Initialize the block cipher with a private key for data decryption.
     * Currently, parameters are not supported.
     * 
     * @param key
     *                the key which has to be used to decrypt data
     * @param params
     *                the algorithm parameters
     * @throws InvalidKeyException
     *                 if the given key is inappropriate for initializing this
     *                 cipher.
     */
    protected void initCipherDecrypt(Key key, AlgorithmParameterSpec params)
	    throws InvalidKeyException {

	if (!(key instanceof McEliecePrivateKey)) {
	    reset();
	    throw new InvalidKeyException("unsupported type");
	}
	privKey = (McEliecePrivateKey) key;

	n = privKey.getN();
	k = privKey.getK();

	maxPlainTextSize = (k >> 3);
	cipherTextSize = n >> 3;
    }

    /**
     * Encrypt a plaintext.
     * 
     * @param input
     *                the plaintext
     * @return the ciphertext
     */
    protected byte[] messageEncrypt(byte[] input) {
	GF2Vector m = computeMessageRepresentative(input);
	GF2Vector z = new GF2Vector(n, t, sr);

	GF2Matrix g = pubKey.getG();
	Vector mG = g.leftMultiply(m);
	GF2Vector mGZ = (GF2Vector) mG.add(z);

	return mGZ.getEncoded();
    }

    private GF2Vector computeMessageRepresentative(byte[] input) {
	byte[] data = new byte[maxPlainTextSize + ((k & 0x07) != 0 ? 1 : 0)];
	System.arraycopy(input, 0, data, 0, input.length);
	data[input.length] = 0x01;
	return GF2Vector.OS2VP(k, data);
    }

    /**
     * Decrypt a ciphertext.
     * 
     * @param input
     *                the ciphertext
     * @return the plaintext
     * @throws BadPaddingException
     *                 if the ciphertext is invalid.
     */
    protected byte[] messageDecrypt(byte[] input) throws BadPaddingException {
	GF2Vector vec = GF2Vector.OS2VP(n, input);

	GF2mField field = privKey.getField();
	PolynomialGF2mSmallM gp = privKey.getGoppaPoly();
	GF2Matrix sInv = privKey.getSInv();
	Permutation p1 = privKey.getP1();
	Permutation p2 = privKey.getP2();
	GF2Matrix h = privKey.getH();
	PolynomialGF2mSmallM[] qInv = privKey.getQInv();

	// compute permutation P = P1 * P2
	Permutation p = p1.rightMultiply(p2);

	// compute P^-1
	Permutation pInv = p.computeInverse();

	// compute c P^-1
	GF2Vector cPInv = (GF2Vector) vec.multiply(pInv);

	// compute syndrome of c P^-1
	GF2Vector syndrome = (GF2Vector) h.rightMultiply(cPInv);

	// decode syndrome
	GF2Vector z = GoppaCode.syndromeDecode(syndrome, field, gp, qInv);
	GF2Vector mSG = (GF2Vector) cPInv.add(z);

	// multiply codeword with P1 and error vector with P
	mSG = (GF2Vector) mSG.multiply(p1);
	z = (GF2Vector) z.multiply(p);

	// extract mS (last k columns of mSG)
	GF2Vector mS = mSG.extractRightVector(k);

	// compute plaintext vector
	GF2Vector mVec = (GF2Vector) sInv.leftMultiply(mS);

	// compute and return plaintext
	return computeMessage(mVec);
    }

    private byte[] computeMessage(GF2Vector mr) throws BadPaddingException {
	byte[] mrBytes = mr.getEncoded();
	// find first non-zero byte
	int index;
	for (index = mrBytes.length - 1; index >= 0 && mrBytes[index] == 0; index--)
	    ;

	// check if padding byte is valid
	if (mrBytes[index] != 0x01) {
	    throw new BadPaddingException("invalid ciphertext");
	}

	// extract and return message
	byte[] mBytes = new byte[index];
	System.arraycopy(mrBytes, 0, mBytes, 0, index);
	return mBytes;
    }

    private void reset() {
	privKey = null;
	pubKey = null;
	n = 0;
	k = 0;
	t = 0;
	buf = new ByteArrayOutputStream();
    }

}
