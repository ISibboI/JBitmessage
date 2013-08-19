package sibbo.bitmessage.crypt;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECPublicKeySpec;
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
import org.bouncycastle.math.ec.ECPoint;

import sibbo.bitmessage.Options;
import sibbo.bitmessage.network.protocol.EncryptedMessage;
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
	private java.security.spec.ECParameterSpec newECKeyParameters;

	private KeyPairGenerator skpg;
	private ECParameterSpec ecSigningGenSpec;
	private java.security.spec.ECParameterSpec newECSigningKeyParameters;

	public boolean initialize() {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		try {
			kpg = KeyPairGenerator.getInstance("ECIES", "BC");
			ecGenSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
			kpg.initialize(ecGenSpec, new SecureRandom());
			newECKeyParameters = ((JCEECPublicKey) kpg.generateKeyPair().getPublic()).getParams();

			skpg = KeyPairGenerator.getInstance("ECDSA", "BC");
			ecSigningGenSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
			skpg.initialize(ecSigningGenSpec, new SecureRandom());
			newECSigningKeyParameters = ((JCEECPublicKey) skpg.generateKeyPair().getPublic()).getParams();
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
	 * @param publicSigningKey
	 *            The public signing key.
	 * @return True if the signature is valid, false otherwise.
	 */
	public boolean verifySignature(byte[] data, byte[] signature, JCEECPublicKey publicSigningKey) {
		try {
			Signature sig = Signature.getInstance("ECDSA", "BC");
			sig.initVerify(publicSigningKey);
			sig.update(data);

			return sig.verify(signature);
		} catch (NoSuchAlgorithmException | NoSuchProviderException | SignatureException | InvalidKeyException e) {
			LOG.log(Level.SEVERE, "No ECDSA signing available.", e);
			System.exit(1);
			return false;
		}
	}

	public byte[] sign(byte[] data, JCEECPrivateKey key) {
		try {
			Signature sig = Signature.getInstance("ECDSA", "BC");
			sig.initSign(key, new SecureRandom());
			sig.update(data);

			return sig.sign();
		} catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | SignatureException e) {
			LOG.log(Level.SEVERE, "No ECDSA signing available.", e);
			System.exit(1);
			return null;
		}
	}

	/**
	 * Tries to decrypt the given data using the given private key.
	 * 
	 * @param encrypted
	 *            The data to decrypt.
	 * @return A KeyDataPair containing the key that was used for decryption and
	 *         the decrypted data.
	 */
	public byte[] decrypt(EncryptedMessage encrypted, JCEECPrivateKey key) {
		ECPoint point = encrypted.getPublicKey().getQ().multiply(key.getD());

		byte[] tmpKey = Digest.sha512(Util.getUnsignedBytes(point.getX().toBigInteger(), 32));
		byte[] key_e = Arrays.copyOf(tmpKey, 32);

		byte[] plain = doAES(key_e, encrypted.getIV(), encrypted.getEncrypted(), false);

		return plain;
	}

	public boolean checkMac(EncryptedMessage encrypted, JCEECPrivateKey key) {
		ECPoint point = encrypted.getPublicKey().getQ().multiply(key.getD());

		byte[] tmpKey = Digest.sha512(Util.getUnsignedBytes(point.getX().toBigInteger(), 32));
		byte[] key_m = Arrays.copyOfRange(tmpKey, 32, 64);

		return Arrays.equals(encrypted.getMac(), Digest.hmacSHA256(encrypted.getEncrypted(), key_m));
	}

	/**
	 * Encrypts the given data using the attached private key.
	 * 
	 * @param plain
	 *            The data and key.
	 * @return The data encrypted with the given key.
	 */
	public EncryptedMessage encrypt(byte[] plain, JCEECPublicKey key) {
		KeyPair random = generateEncryptionKeyPair();

		ECPoint point = key.getQ().multiply(((JCEECPrivateKey) random.getPrivate()).getD());
		byte[] tmpKey = deriveKey(point);
		byte[] key_e = Arrays.copyOfRange(tmpKey, 0, 32);
		byte[] key_m = Arrays.copyOfRange(tmpKey, 32, 64);
		byte[] iv = new byte[16];
		new SecureRandom().nextBytes(iv);

		byte[] encrypted = doAES(key_e, iv, plain, true);
		byte[] mac = Digest.hmacSHA256(encrypted, key_m);

		return new EncryptedMessage(iv, (JCEECPublicKey) random.getPublic(), encrypted, mac);
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
	 * Derives a 512 bit key from the given ECPoint.
	 * 
	 * @param p
	 *            An ECPoint.
	 * @return A 512 bit key.
	 */
	private byte[] deriveKey(ECPoint p) {
		return Digest.sha512(Util.getUnsignedBytes(p.getX().toBigInteger(), 32));
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
	public KeyPair createKeyPairWithPrivateKey(PrivateKey key) {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * Generates a new random ECIES key pair.
	 * 
	 * @return A new random ECIES key pair.
	 */
	public KeyPair generateEncryptionKeyPair() {
		synchronized (kpg) {
			return kpg.generateKeyPair();
		}
	}

	/**
	 * Creates a JCEECPublicKey with the given coordinates. The key will have
	 * valid parameters.
	 * 
	 * @param x
	 *            The x coordinate on the curve.
	 * @param y
	 *            The y coordinate on the curve.
	 * @return A JCEECPublicKey with the given coordinates.
	 */
	public JCEECPublicKey createPublicEncryptionKey(BigInteger x, BigInteger y) {
		java.security.spec.ECPoint w = new java.security.spec.ECPoint(x, y);
		/*
		 * ECPoint . Fp ( ecGenSpec . getCurve ( ) , new ECFieldElement . Fp ( (
		 * ( ECCurve . Fp ) ecGenSpec . getCurve ( ) ) . getQ ( ) , x ) , new
		 * ECFieldElement . Fp ( ( ( ECCurve . Fp ) ecGenSpec . getCurve ( ) ) .
		 * getQ ( ) , y ) ) ;
		 */
		return new JCEECPublicKey("ECDH", new ECPublicKeySpec(w, newECKeyParameters));
	}

	/**
	 * Generates a new random ECDSA key pair.
	 * 
	 * @return A new random ECDSA key pair.
	 */
	public KeyPair generateSigningKeyPair() {
		synchronized (skpg) {
			return skpg.generateKeyPair();
		}
	}
}