package de.flexiprovider.pqc.ecc.niederreiter;

import de.flexiprovider.api.AsymmetricBlockCipher;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.exceptions.BadPaddingException;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.keys.Key;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.math.IntegerFunctions;
import de.flexiprovider.common.math.codingtheory.GF2mField;
import de.flexiprovider.common.math.codingtheory.GoppaCode;
import de.flexiprovider.common.math.codingtheory.PolynomialGF2mSmallM;
import de.flexiprovider.common.math.linearalgebra.GF2Matrix;
import de.flexiprovider.common.math.linearalgebra.GF2Vector;
import de.flexiprovider.common.math.linearalgebra.Permutation;
import de.flexiprovider.common.math.linearalgebra.Vector;
import de.flexiprovider.pqc.ecc.Conversions;

/**
 * This class implements the Niederreiter Public Key Cryptosystem which is based
 * on error correcting codes. The class extends <a
 * href="de.flexiprovider.common.cipher.AsymmetricBasicCipher"
 * >de.flexiprovider.common.cipher.AsymmetricBasicCipher</a>.
 * <p>
 * The NiederreiterPKC can be used as follows:
 * <p>
 * To encrypt a message, the following steps have to be performed:
 * 
 * <pre>
 * // The message which should be encrypted
 * String message = &quot;secret message&quot;;
 * byte[] messageBytes = message.getBytes();
 * 
 * // Generate KeySpec from encoded Niederreiter public key:
 * KeySpec publicKeySpec = new X509EncodedKeySpec(encPublicKey);
 * 
 * // Initialize the Niederreiter key factory:&lt;br/&gt;
 * KeyFactory keyFactory = KeyFactory.getInstance(&quot;Niederreiter&quot;, &quot;FlexiPQC&quot;);
 * 
 * // Decode Niederreiter public key:&lt;br/&gt;
 * PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
 * 
 * // The source of randomness
 * SecureRandom sr = Registry.getSecureRandom();
 * 
 * // Obtain a NiederreiterPKC Cipher Object
 * Cipher cipher = Cipher.getInstance(&quot;NiederreiterPKCS&quot;);
 * 
 * // Initialize the cipher
 * cipher.init(Cipher.ENCRYPT_MODE, publicKey, sr);
 * 
 * // Finally encrypt the message
 * byte[] ciphertextBytes = cipher.doFinal(messageBytes);
 * </pre>
 * 
 * To decrypt a message, the following steps have to be performed:
 * 
 * <pre>
 * // Generate KeySpec from encoded Niederreiter private key:
 * KeySpec publicKeySpec = new PKCS8EncodedKeySpec(encPrivateKey);
 * 
 * // Initialize the Niederreiter key factory:&lt;br/&gt;
 * KeyFactory keyFactory = KeyFactory.getInstance(&quot;Niederreiter&quot;, &quot;FlexiPQC&quot;);
 * 
 * // Decode Niederreiter private key:&lt;br/&gt;
 * PublicKey privateKey = keyFactory.generatePrivate(privateKeySpec);
 * 
 * // Obtain a NiederreiterPKC Cipher Object
 * Cipher cipher = Cipher.getInstance(&quot;NiederreiterPKCS&quot;);
 * 
 * // Initialize the cipher
 * cipher.init(Cipher.DECRYPT_MODE, privateKey);
 * 
 * // Finally decrypt the message
 * byte[] messageBytes = cipher.doFinal(ciphertextBytes);
 * String message = new String(messageBytes);
 * </pre>
 * 
 * @see AsymmetricBlockCipher
 * @author Elena Klintsevich
 */
public class NiederreiterPKCS extends AsymmetricBlockCipher {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = NiederreiterKeyFactory.OID + ".1";

	// the public key
	private NiederreiterPrivateKey privKey;

	// the private key
	private NiederreiterPublicKey pubKey;

	/**
	 * Return the name of this cipher.
	 * 
	 * @return "Niederreiter"
	 */
	public String getName() {
		return "Niederreiter";
	}

	/**
	 * Return the key size of the given key object. Checks whether the key
	 * object is an instance of <tt>NiederreiterPublicKey</tt> or
	 * <tt>NiederreiterPrivateKey</tt>.
	 * 
	 * @param key
	 *            the key object
	 * @return the key size of the given key object
	 * @throws InvalidKeyException
	 *             if the key is invalid
	 */
	public int getKeySize(Key key) throws InvalidKeyException {
		if (key instanceof NiederreiterPrivateKey) {
			return ((NiederreiterPrivateKey) key).getN();
		}
		if (key instanceof NiederreiterPublicKey) {
			return ((NiederreiterPublicKey) key).getN();
		}
		throw new InvalidKeyException("unsupported type");
	}

	/**
	 * Initialize the cipher with a public key and parameters for encryption.
	 * 
	 * @param key
	 *            the key to use for encryption
	 * @param params
	 *            the algorithm parameters
	 * @param secureRandom
	 *            the source of randomness
	 * @throws InvalidKeyException
	 *             if the given key is inappropriate for initializing this
	 *             cipher.
	 */
	protected void initCipherEncrypt(Key key, AlgorithmParameterSpec params,
			SecureRandom secureRandom) throws InvalidKeyException {

		if (!(key instanceof NiederreiterPublicKey)) {
			throw new InvalidKeyException("unsupported type");
		}
		pubKey = (NiederreiterPublicKey) key;

		FlexiBigInt binomial = IntegerFunctions.binomial(pubKey.getN(), pubKey
				.getT());
		// the maximal plaintext size is computed conservatively so that
		// encryption always works. Because of this, some bits may be wasted.
		maxPlainTextSize = ((binomial.bitLength() - 1) >> 3) - 1;
		cipherTextSize = (pubKey.getH().getNumRows() + 7) >> 3;
	}

	/**
	 * Initialize the cipher with a private key and parameters for decryption.
	 * 
	 * @param key
	 *            the key to use for decryption
	 * @param params
	 *            the algorithm parameters
	 * @throws InvalidKeyException
	 *             if the given key is inappropriate for initializing this
	 *             cipher.
	 */
	protected void initCipherDecrypt(Key key, AlgorithmParameterSpec params)
			throws InvalidKeyException {

		if (!(key instanceof NiederreiterPrivateKey)) {
			throw new InvalidKeyException("unsupported type");
		}
		privKey = (NiederreiterPrivateKey) key;

		FlexiBigInt binomial = IntegerFunctions.binomial(pubKey.getN(), pubKey
				.getT());
		// the maximal plaintext size is computed conservatively so that
		// encryption always works. Because of this, some bits may be
		// wasted.
		maxPlainTextSize = ((binomial.bitLength() - 1) >> 3) - 1;
		cipherTextSize = (privKey.getK() + 7) >> 3;

	}

	/**
	 * Encrypt a plaintext given in <tt>input</tt>.
	 * 
	 * @param input
	 *            the plaintext
	 * @return the ciphertext
	 */
	protected byte[] messageEncrypt(byte[] input) {
		byte[] data = padMessage(input);
		GF2Vector m = Conversions.encode(pubKey.getN(), pubKey.getT(), data);
		Vector hm = pubKey.getH().rightMultiplyRightCompactForm(m);
		return hm.getEncoded();
	}

	private byte[] padMessage(byte[] input) {
		byte[] result = new byte[input.length + 1];
		result[0] = 0x01;
		System.arraycopy(input, 0, result, 1, input.length);
		return result;
	}

	/**
	 * Decrypt a ciphertext given in <tt>input</tt>.
	 * 
	 * @param input
	 *            the ciphertext
	 * @return the plaintext
	 * @throws BadPaddingException
	 *             if the ciphertext is invalid.
	 */
	protected byte[] messageDecrypt(byte[] input) throws BadPaddingException {
		GF2mField field = privKey.getField();
		int n = privKey.getN();
		int k = privKey.getK();
		int t = privKey.getT();
		PolynomialGF2mSmallM gp = privKey.getGoppaPoly();
		GF2Matrix matrixS = privKey.getSInv();
		Permutation p = privKey.getP();
		PolynomialGF2mSmallM[] sqRootMatrix = privKey.getQInv();

		GF2Vector c = GF2Vector.OS2VP(k, input);
		GF2Vector syndrome = (GF2Vector) matrixS.rightMultiply(c);
		GF2Vector pe = GoppaCode.syndromeDecode(syndrome, field, gp,
				sqRootMatrix);
		GF2Vector e = (GF2Vector) pe.multiply(p);

		byte[] data = Conversions.decode(n, t, e);
		return unpadMessage(data);
	}

	private byte[] unpadMessage(byte[] input) throws BadPaddingException {
		int index;
		for (index = 0; index < input.length && input[index] == 0; index++)
			;

		// check if padding byte is valid
		if (input[index] != 0x01) {
			throw new BadPaddingException("invalid ciphertext");
		}

		// extract and return message
		byte[] result = new byte[input.length - index - 1];
		System.arraycopy(input, index + 1, result, 0, input.length - index - 1);
		return result;
	}

}
