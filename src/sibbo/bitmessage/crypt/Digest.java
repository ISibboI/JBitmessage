package sibbo.bitmessage.crypt;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

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
	 * @param bytes The input for sha512.
	 * @param digestLength The number of bytes to return.
	 * @return The first {@code digestLength} bytes of the sha512 sum of
	 *         {@code bytes}, or null, if SHA-512 is not supported.
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
}