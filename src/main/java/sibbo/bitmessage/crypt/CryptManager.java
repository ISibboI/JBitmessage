package sibbo.bitmessage.crypt;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.IEKeySpec;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.math.ec.ECCurve;

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
		initialize();
	}

	public static CryptManager getInstance() {
		if (instance == null) {
			instance = new CryptManager();
		}

		return instance;
	}

	private KeyPairGenerator kpg;
	private IESParameterSpec iesps;

	public boolean initialize() {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		
		try {
			kpg = KeyPairGenerator.getInstance("ECIES", "BC");
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			LOG.log(Level.SEVERE, "No ECIES cryptography available!", e);
			return false;
		}
		
		iesps = new IESParameterSpec(new byte[]{1, 2, 3, 4, 5, 6, 7, 8}, new byte[]{8, 7, 6, 5, 4, 3, 2, 1}, 128);

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
	public KeyDataPair tryDecryption(KeyDataPair encrypted) {
		Cipher cipher = null;

			try {
				cipher = Cipher.getInstance("ECIES", "BC");
			} catch (NoSuchAlgorithmException | NoSuchProviderException
					| NoSuchPaddingException e) {
				LOG.log(Level.SEVERE, "No ECIES cryptography available!", e);
				return null;
			}

		try {
			cipher.init(Cipher.DECRYPT_MODE, new IEKeySpec(encrypted.getKey()
					.getPrivate(), encrypted.getKey().getPublic()), iesps);
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			LOG.log(Level.SEVERE, "Invalid Key", e);
			return null;
		}

		try {
			return new KeyDataPair(encrypted.getKey(), cipher.doFinal(encrypted.getData()));
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			LOG.log(Level.SEVERE, "Could not encrypt message.", e);
			return null;
		}
	}

	/**
	 * Encrypts the given data using the attached private key.
	 * 
	 * @param plain
	 *            The data and key.
	 * @return The data encrypted with the given key.
	 */
	public KeyDataPair encrypt(KeyDataPair plain) {
		Cipher cipher = null;

		synchronized (kpg) {
			try {
				cipher = Cipher.getInstance("ECIES", "BC");
			} catch (NoSuchAlgorithmException | NoSuchProviderException
					| NoSuchPaddingException e) {
				LOG.log(Level.SEVERE, "No ECIES cryptography available!", e);
				return null;
			}
		}

		try {
			cipher.init(Cipher.ENCRYPT_MODE, new IEKeySpec(plain.getKey()
					.getPrivate(), plain.getKey().getPublic()), iesps);
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			LOG.log(Level.SEVERE, "Invalid Key", e);
			return null;
		}

		try {
			return new KeyDataPair(plain.getKey(), cipher.doFinal(plain.getData()));
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			LOG.log(Level.SEVERE, "Could not encrypt message.", e);
			return null;
		}
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

	/**
	 * Creates a KeyPair containing only the given private key. The value of the public key will be undefined.
	 * @param privateEncryptionKey The private encryption key.
	 * @return A KeyPair containing only the given private key.
	 */
	public KeyPair createKeyPairWithPrivateKey(byte[] privateEncryptionKey) {
		// TODO Auto-generated method stub
		return null;
	}
}