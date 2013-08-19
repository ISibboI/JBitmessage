package sibbo.bitmessage.crypt;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.JCEECPrivateKey;
import org.bouncycastle.jce.provider.JCEECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

import sibbo.bitmessage.Options;
import sibbo.bitmessage.network.protocol.Util;

public final class CryptManager {
	private static final Logger LOG = Logger.getLogger(CryptManager.class.getName());

	public static CryptManager instance;

	/**
	 * Singleton.
	 */
	private CryptManager() {
		initialize();
	}

	public static CryptManager getInstance() {
		if (instance == null) {
			instance = new CryptManager();
		}

		return instance;
	}

	private KeyPairGenerator kpg;
	private ECParameterSpec ecGenSpec;

	public boolean initialize() {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		try {
			kpg = KeyPairGenerator.getInstance("ECIES", "BC");
			ecGenSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
			kpg.initialize(ecGenSpec, new SecureRandom());
		} catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
			LOG.log(Level.SEVERE, "No ECIES cryptography available!", e);
			return false;
		}

		return true;
	}

	/**
	 * Checks if the given data was signed with the private key belonging to the
	 * given public key.
	 * 
	 * @param data
	 *            The signed data.
	 * @param signature
	 *            The signature.
	 * @param key
	 *            The public signing key.
	 * @return True if the signature is valid, false otherwise.
	 */
	public boolean checkSignature(byte[] data, byte[] signature, byte[] key) {
		// TODO Auto-generated method stub
		return true;
	}

	/**
	 * Tries to decrypt the given data using the given private key.
	 * 
	 * @param encrypted
	 *            The data to decrypt.
	 * @return A KeyDataPair containing the key that was used for decryption and
	 *         the decrypted data or null, if the data could not be decrypted
	 *         with the given key.
	 */
	public KeyDataPair tryDecryption(KeyDataPair encrypted) {
		byte[] iv = new byte[16];
		System.arraycopy(encrypted.getData(), 0, iv, 0, 16);
		byte[] mac = new byte[32];
		System.arraycopy(encrypted.getData(), encrypted.getData().length - 32, mac, 0, 32);

		int xlength = Util.getShort(encrypted.getData(), 18);
		BigInteger x = getUnsignedBigInteger(encrypted.getData(), 20, xlength);
		int ylength = Util.getShort(encrypted.getData(), 20 + xlength);
		BigInteger y = getUnsignedBigInteger(encrypted.getData(), 22 + xlength, ylength);

		ECPoint point = new ECPoint.Fp(ecGenSpec.getCurve(), new ECFieldElement.Fp(
				((ECCurve.Fp) ecGenSpec.getCurve()).getQ(), x), new ECFieldElement.Fp(
				((ECCurve.Fp) ecGenSpec.getCurve()).getQ(), y));

		point = point.multiply(((JCEECPrivateKey) encrypted.getKey().getPrivate()).getD());

		byte[] data = new byte[encrypted.getData().length - 16 - 32 - 6 - xlength - ylength];
		System.arraycopy(encrypted.getData(), 16 + 6 + xlength + ylength, data, 0, data.length);

		byte[] tmpKey = Digest.sha512(getBytes(point.getX().toBigInteger(), 32));
		byte[] key_e = Arrays.copyOf(tmpKey, 32);
		byte[] key_m = Arrays.copyOfRange(tmpKey, 32, 64);

		if (!Arrays.equals(mac, Digest.hmacSHA256(data, key_m))) {
			return null;
		}

		byte[] plain = doAES(key_e, iv, encrypted.getData(), false);

		return new KeyDataPair(encrypted.getKey(), plain);
	}

	/**
	 * Encrypts the given data using the attached private key.
	 * 
	 * @param plain
	 *            The data and key.
	 * @return The data encrypted with the given key.
	 */
	public KeyDataPair encrypt(KeyDataPair plain) {
		KeyPair random = null;

		synchronized (kpg) {
			random = kpg.generateKeyPair();
		}

		ECPoint point = ((JCEECPublicKey) plain.getKey().getPublic()).getQ().multiply(
				((JCEECPrivateKey) random.getPrivate()).getD());
		byte[] tmpKey = deriveKey(point);
		byte[] key_e = Arrays.copyOfRange(tmpKey, 0, 32);
		byte[] key_m = Arrays.copyOfRange(tmpKey, 32, 64);
		byte[] iv = new byte[16];
		new SecureRandom().nextBytes(iv);

		byte[] encrypted = doAES(key_e, iv, plain.getData(), true);
		byte[] mac = Digest.hmacSHA256(encrypted, key_m);

		ECPoint randomPoint = ((JCEECPublicKey) plain.getKey().getPublic()).getQ();

		byte[] result = new byte[16 + 70 + encrypted.length + 32];
		System.arraycopy(iv, 0, result, 0, 16);
		System.arraycopy(new byte[] { 0x02, (byte) 0xCA }, 0, result, 16, 2);
		System.arraycopy(new byte[] { 0x00, 0x20 }, 0, result, 18, 2);
		System.arraycopy(getBytes(randomPoint.getX().toBigInteger(), 32), 0, result, 20, 32);
		System.arraycopy(new byte[] { 0x00, 0x20 }, 0, result, 52, 2);
		System.arraycopy(getBytes(randomPoint.getY().toBigInteger(), 32), 0, result, 54, 32);
		System.arraycopy(encrypted, 0, result, 16 + 70, encrypted.length);
		System.arraycopy(mac, 0, result, 16 + 70 + encrypted.length, 32);

		return new KeyDataPair(plain.getKey(), result);
	}

	/**
	 * En- or decrypts the given data with the given key.
	 * 
	 * @param keyBytes
	 *            The AES key.
	 * @param data
	 *            The data to process.
	 * @param encrypt
	 *            True if the data should be encrypted, false if it should be
	 *            decrypted.
	 * @return The en- or decrypted data.
	 */
	private byte[] doAES(byte[] keyBytes, byte[] iv, byte[] data, boolean encrypt) {
		BlockCipherPadding padding = new PKCS7Padding();
		BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), padding);

		KeyParameter key = new KeyParameter(keyBytes);
		CipherParameters params = new ParametersWithIV(key, iv);

		cipher.init(encrypt, params);

		byte[] buffer = new byte[cipher.getOutputSize(data.length)];
		int length = cipher.processBytes(data, 0, data.length, buffer, 0);

		try {
			length += cipher.doFinal(buffer, length);
		} catch (DataLengthException | IllegalStateException | InvalidCipherTextException e) {
			LOG.log(Level.SEVERE, "Could not execute AES.", e);
			return null;
		}

		return Arrays.copyOf(buffer, length);
	}

	/**
	 * Returns a positive BigInteger from the given bytes. (Big endian)
	 * 
	 * @param data
	 *            The bytes.
	 * @param offset
	 *            The first byte.
	 * @param length
	 *            The amount of bytes to process.
	 * @return A BigInteger from the given bytes.
	 */
	private BigInteger getUnsignedBigInteger(byte[] data, int offset, int length) {
		byte[] value = new byte[length + 1];
		System.arraycopy(data, offset, value, 1, length);

		return new BigInteger(value);
	}

	/**
	 * Returns a byte[] representation of the given big integer, cutting it to
	 * the given length.
	 * 
	 * @param number
	 *            The BigInteger.
	 * @param length
	 *            The maximum length.
	 * @return The last <code>length</code> bytes of the given big integer,
	 *         filled with zeros if necessary.
	 */
	private byte[] getBytes(BigInteger number, int length) {
		byte[] value = number.toByteArray();
		byte[] result = new byte[length];

		int i = value.length == length + 1 ? 1 : 0;
		for (; i < value.length; i++) {
			result[i + length - value.length] = value[i];
		}

		return result;
	}

	/**
	 * Derives a 512 bit key from the given ECPoint.
	 * 
	 * @param p
	 *            An ECPoint.
	 * @return A 512 bit key.
	 */
	private byte[] deriveKey(ECPoint p) {
		return Digest.sha512(getBytes(p.getX().toBigInteger(), 32));
	}

	/**
	 * Checks if the proof of work done for the given data is sufficient.
	 * 
	 * @param data
	 *            The data.
	 * @param nonce
	 *            The POW nonce.
	 * @return True if the pow is sufficient.
	 */
	public boolean checkPOW(byte[] data, byte[] nonce) {
		byte[] initialHash = Digest.sha512(data);
		byte[] hash = Digest.sha512(Digest.sha512(nonce, initialHash));
		long value = Util.getLong(hash);
		long target = getPOWTarget(data.length);

		return value >= 0 && target >= value;
	}

	/**
	 * Returns the POW target for a message with the given length.
	 * 
	 * @param length
	 *            The message length.
	 * @return The POW target for a message with the given length.
	 */
	public long getPOWTarget(int length) {
		// // Testing:
		// return (long) Math.pow(2, 60);

		BigInteger powTarget = BigInteger.valueOf(2);
		powTarget = powTarget.pow(64);
		powTarget = powTarget.divide(BigInteger.valueOf((length
				+ Options.getInstance().getInt("pow.payloadLengthExtraBytes") + 8)
				* Options.getInstance().getInt("pow.averageNonceTrialsPerByte")));

		// Note that we are dividing through at least 8, so that the value is
		// smaller than 2^61 and fits perfectly into a long.
		return powTarget.longValue();
	}

	/**
	 * Does the POW for the given payload.<br />
	 * <b>WARNING: Takes a long time!!!</b>
	 * 
	 * @param payload
	 * @return
	 */
	public byte[] doPOW(byte[] payload) {
		POWCalculator pow = new POWCalculator(getPOWTarget(payload.length), Digest.sha512(payload), Options
				.getInstance().getInt("pow.systemLoad"));
		return pow.execute();
	}

	/**
	 * Creates a KeyPair containing only the given private key. The value of the
	 * public key will be undefined.
	 * 
	 * @param privateEncryptionKey
	 *            The private encryption key.
	 * @return A KeyPair containing only the given private key.
	 */
	public KeyPair createKeyPairWithPrivateKey(byte[] privateEncryptionKey) {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * Generates a new random ECIES key pair.
	 * 
	 * @return A new random ECIES key pair.
	 */
	public KeyPair generateKeyPair() {
		synchronized (kpg) {
			return kpg.generateKeyPair();
		}
	}
}