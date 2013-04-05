package sibbo.bitmessage.crypt;

import java.util.Objects;
import java.util.logging.Logger;

/**
 * A bitmessage address.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 */
public class BMAddress {
	private static final Logger LOG = Logger.getLogger(BMAddress.class
			.getName());

	/** The public signing key. */
	private byte[] publicSigningKey;

	/** The public encryption key. */
	private byte[] publicEncryptionKey;

	/** The ripe hash of the address. */
	private byte[] ripe;

	/** The private signing key. */
	private byte[] privateSigningKey;

	/** The private encryption key. */
	private byte[] privateEncryptionKey;

	/**
	 * Creates a new bitmessage key with the given parameters. The key created
	 * cannot be used for encryption.
	 * 
	 * @param publicSigningKey The public signing key.
	 * @param publicEncryptionKey The public encryption key.
	 */
	public BMAddress(byte[] publicSigningKey, byte[] publicEncryptionKey) {
		Objects.requireNonNull(publicSigningKey,
				"publicSigningKey must not be null.");
		Objects.requireNonNull(publicEncryptionKey,
				"publicEncryptionKey must not be null.");

		if (publicSigningKey.length != 64) {
			throw new IllegalArgumentException(
					"publicSigningKey must have a length of 64.");
		}

		if (publicEncryptionKey.length != 64) {
			throw new IllegalArgumentException(
					"publicEncryptionKey must have a length of 64.");
		}

		this.publicSigningKey = publicSigningKey;
		this.publicEncryptionKey = publicEncryptionKey;

		this.ripe = Digest.keyDigest(publicSigningKey, publicEncryptionKey);
	}

	/**
	 * Creates a new bitmessage key with the given parameters. The key created
	 * cannot be used for encryption.
	 * 
	 * @param publicSigningKey The public signing key.
	 * @param publicEncryptionKey The public encryption key.
	 * @param ripe The ripe hash of the key.
	 */
	public BMAddress(byte[] publicSigningKey, byte[] publicEncryptionKey,
			byte[] ripe) {
		Objects.requireNonNull(publicSigningKey,
				"publicSigningKey must not be null.");
		Objects.requireNonNull(publicEncryptionKey,
				"publicEncryptionKey must not be null.");
		Objects.requireNonNull(ripe, "ripe must not be null.");

		if (publicSigningKey.length != 64) {
			throw new IllegalArgumentException(
					"publicSigningKey must have a length of 64.");
		}

		if (publicEncryptionKey.length != 64) {
			throw new IllegalArgumentException(
					"publicEncryptionKey must have a length of 64.");
		}

		if (ripe.length != 64) {
			throw new IllegalArgumentException("ripe must have a length of 64.");
		}

		this.publicSigningKey = publicSigningKey;
		this.publicEncryptionKey = publicEncryptionKey;
		this.ripe = ripe;
	}

	public byte[] getPublicSigningKey() {
		return publicSigningKey;
	}

	public byte[] getPublicEncryptionKey() {
		return publicEncryptionKey;
	}

	public byte[] getRipe() {
		return ripe;
	}

	public byte[] getPrivateSigningKey() {
		return privateSigningKey;
	}

	public byte[] getPrivateEncryptionKey() {
		return privateEncryptionKey;
	}
}