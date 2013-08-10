package sibbo.bitmessage.crypt;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import sibbo.bitmessage.Options;
import sibbo.bitmessage.crypt.Digest;
import sibbo.bitmessage.crypt.KeyDataPair;
import sibbo.bitmessage.crypt.POWCalculator;
import sibbo.bitmessage.network.protocol.Util;

public final class CryptManager {
	private static final Logger LOG = Logger.getLogger(CryptManager.class
			.getName());

	public static CryptManager instance;

	/**
	 * Singleton.
	 */
	private CryptManager() {
	}

	public static CryptManager getInstance() {
		if (instance == null) {
			instance = new CryptManager();
		}

		return instance;
	}

	private KeyPairGenerator kpg;
	private Cipher cipher;
	private ECGenParameterSpec ecsp;

	public boolean initialize() {
		try {
			kpg = KeyPairGenerator.getInstance("EC");
		} catch (NoSuchAlgorithmException e) {
			LOG.log(Level.SEVERE, "No EC cryptography available!", e);
			return false;
		}

		try {
			cipher = Cipher.getInstance("AES-256-CBC");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			LOG.log(Level.SEVERE, "No AES-256-CBC cryptography available!", e);
			return false;
		}

		ecsp = new ECGenParameterSpec("sect283r1");

		try {
			kpg.initialize(ecsp);
		} catch (InvalidAlgorithmParameterException e) {
			LOG.log(Level.SEVERE, "", e);
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
	 * @param key
	 *            The key to try.
	 * @return A KeyDataPair containing the key that was used for decryption and
	 *         the decrypted data or null, if the data could not be decrypted
	 *         with the given key.
	 */
	public KeyDataPair tryDecryption(byte[] encrypted, byte[] key) {
		return null;
		// TODO Fill
	}

	/**
	 * Encrypts the given data using the attached private key.
	 * 
	 * @param plain
	 *            The data and key.
	 * @return The data encrypted with the given key.
	 */
	public KeyDataPair encrypt(KeyDataPair plain) {
		KeyPair keyPair = plain.getKey();
		PrivateKey priv = keyPair.getPrivate();
		
		return null;
		//TODO finish
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
		powTarget = powTarget.divide(BigInteger
				.valueOf((length
						+ Options.getInstance().getInt(
								"pow.payloadLengthExtraBytes") + 8)
						* Options.getInstance().getInt(
								"pow.averageNonceTrialsPerByte")));

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
		POWCalculator pow = new POWCalculator(getPOWTarget(payload.length),
				Digest.sha512(payload), Options.getInstance().getInt(
						"pow.systemLoad"));
		return pow.execute();
	}
}