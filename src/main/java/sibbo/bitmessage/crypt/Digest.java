package sibbo.bitmessage.crypt;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.JCEECPublicKey;

import sibbo.bitmessage.network.protocol.Util;

/**
 * Provides easy access for several hash-functions.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 */
public final class Digest {
	private static final Logger LOG = Logger.getLogger(Digest.class.getName());

	/** Utility class */
	private Digest() {
	}

	/**
	 * Returns the first {@code digestLength} bytes of the sha512 sum of
	 * {@code bytes}.
	 * 
	 * @param bytes
	 *            The input for sha512.
	 * @param digestLength
	 *            The number of bytes to return.
	 * @return The first {@code digestLength} bytes of the sha512 sum of
	 *         {@code bytes}..
	 */
	public static byte[] sha512(byte[] bytes, int digestLength) {
		MessageDigest sha512;

		try {
			sha512 = MessageDigest.getInstance("SHA-512");
			byte[] sum = sha512.digest(bytes);
			return Arrays.copyOf(sum, digestLength);
		} catch (NoSuchAlgorithmException e) {
			LOG.log(Level.SEVERE, "SHA-512 not supported!", e);
			System.exit(1);
			return null;
		}
	}

	/**
	 * Returns the sha512 sum of {@code bytes}.
	 * 
	 * @param bytes
	 *            The input for sha512.
	 * @return The sha512 sum of {@code bytes}.
	 */
	public static byte[] sha512(byte[] data) {
		return sha512(data, 64);
	}

	/**
	 * Returns the sha512 sum of all given bytes.
	 * 
	 * @param data
	 *            The bytes
	 * @return The sha512 sum of all given bytes.
	 */
	public static byte[] sha512(byte[]... data) {
		MessageDigest sha512;

		try {
			sha512 = MessageDigest.getInstance("SHA-512");

			for (byte[] bytes : data) {
				sha512.update(bytes);
			}

			return sha512.digest();
		} catch (NoSuchAlgorithmException e) {
			LOG.log(Level.SEVERE, "SHA-512 not supported!", e);
			System.exit(1);
			return null;
		}
	}

	/**
	 * Returns the ripemd160 sum of the given data.
	 * 
	 * @param data
	 *            The data.
	 * @return The ripemd160 sum of the given data.
	 */
	public static byte[] ripemd160(byte[] data) {
		MessageDigest ripemd160;

		try {
			ripemd160 = MessageDigest.getInstance("ripemd160");

			return ripemd160.digest(data);
		} catch (NoSuchAlgorithmException e) {
			LOG.log(Level.SEVERE, "ripemd160 not supported!", e);
			System.exit(1);
			return null;
		}
	}

	/**
	 * Calculates the digest of the given key pair.
	 * 
	 * @param publicSigningKey
	 *            The public signing key.
	 * @param publicEncryptionKey
	 *            The public encryption key.
	 * @return The digest of the given key pair.
	 */
	public static byte[] keyDigest(JCEECPublicKey publicSigningKey, JCEECPublicKey publicEncryptionKey) {
		return ripemd160(sha512(Util.getBytes(publicSigningKey), Util.getBytes(publicEncryptionKey)));
	}

	/**
	 * Calculates the HmacSHA256 from the given key and data.
	 * 
	 * @param data
	 *            The data.
	 * @param key
	 *            The key.
	 * @return The HmacSHA256.
	 */
	public static byte[] hmacSHA256(byte[] data, byte[] key) {
		try {
			Mac mac = Mac.getInstance("HmacSHA256", "BC");
			mac.init(new SecretKeySpec(key, "HmacSHA256"));
			return mac.doFinal(data);
		} catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException e) {
			LOG.log(Level.SEVERE, "Could not generate HMAC.", e);
			System.exit(1);
			return null;
		}
	}
}