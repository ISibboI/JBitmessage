package sibbo.bitmessage.crypt;

import java.util.Objects;
import java.util.logging.Logger;

import org.bouncycastle.jce.provider.JCEECPrivateKey;
import org.bouncycastle.jce.provider.JCEECPublicKey;

import sibbo.bitmessage.network.protocol.Util;

/**
 * A bitmessage address.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 */
public class BMAddress {
	private static final Logger LOG = Logger.getLogger(BMAddress.class.getName());

	/** The public signing key. */
	private JCEECPublicKey publicSigningKey;

	/** The public encryption key. */
	private JCEECPublicKey publicEncryptionKey;

	/** The ripe hash of the address. */
	private byte[] ripe;

	/** The private signing key. */
	private JCEECPrivateKey privateSigningKey;

	/** The private encryption key. */
	private JCEECPrivateKey privateEncryptionKey;

	/**
	 * Creates a new bitmessage key with the given parameters. The key created
	 * cannot be used for encryption.
	 * 
	 * @param publicSigningKey
	 *            The public signing key.
	 * @param publicEncryptionKey
	 *            The public encryption key.
	 */
	public BMAddress(JCEECPublicKey publicSigningKey, JCEECPublicKey publicEncryptionKey) {
		Objects.requireNonNull(publicSigningKey, "publicSigningKey must not be null.");
		Objects.requireNonNull(publicEncryptionKey, "publicEncryptionKey must not be null.");

		this.publicSigningKey = publicSigningKey;
		this.publicEncryptionKey = publicEncryptionKey;

		this.ripe = Digest.keyDigest(publicSigningKey, publicEncryptionKey);
	}

	/**
	 * Creates a new bitmessage key with the given parameters. The key created
	 * cannot be used for encryption.
	 * 
	 * @param publicSigningKey
	 *            The public signing key.
	 * @param publicEncryptionKey
	 *            The public encryption key.
	 * @param ripe
	 *            The ripe hash of the key.
	 */
	public BMAddress(JCEECPublicKey publicSigningKey, JCEECPublicKey publicEncryptionKey, byte[] ripe) {
		Objects.requireNonNull(publicSigningKey, "publicSigningKey must not be null.");
		Objects.requireNonNull(publicEncryptionKey, "publicEncryptionKey must not be null.");
		Objects.requireNonNull(ripe, "ripe must not be null.");

		if (ripe.length != 20) {
			throw new IllegalArgumentException("ripe must have a length of 20.");
		}

		this.publicSigningKey = publicSigningKey;
		this.publicEncryptionKey = publicEncryptionKey;
		this.ripe = ripe;
	}

	public JCEECPublicKey getPublicSigningKey() {
		return publicSigningKey;
	}

	public JCEECPublicKey getPublicEncryptionKey() {
		return publicEncryptionKey;
	}

	public byte[] getRipe() {
		return ripe;
	}

	public JCEECPrivateKey getPrivateSigningKey() {
		return privateSigningKey;
	}

	public JCEECPrivateKey getPrivateEncryptionKey() {
		return privateEncryptionKey;
	}

	/**
	 * Returns true if the given address version is supported.
	 * 
	 * @param addressVersion
	 *            The address version to check.
	 * @return True if the given address version is supported.
	 */
	public static boolean isSupported(long addressVersion) {
		return addressVersion == 2;
	}

	@Override
	public int hashCode() {
		return Util.getInt(ripe);
	}

	@Override
	public boolean equals(Object o) {
		if (o instanceof BMAddress) {
			BMAddress b = (BMAddress) o;

			return publicEncryptionKey.equals(b.publicEncryptionKey) && publicSigningKey.equals(b.publicSigningKey);
		} else {
			return false;
		}
	}
}