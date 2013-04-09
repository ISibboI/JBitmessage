package sibbo.bitmessage.crypt;

import java.util.Objects;
import java.util.logging.Logger;

/**
 * A key that belongs to some data.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 */
public class KeyDataPair {
	private static final Logger LOG = Logger.getLogger(KeyDataPair.class
			.getName());

	/** The key. */
	private byte[] key;

	/** The data. */
	private byte[] data;

	/**
	 * Creates a new key-data pair with the given key and data.
	 * 
	 * @param key The key.
	 * @param data The data.
	 */
	public KeyDataPair(byte[] key, byte[] data) {
		Objects.requireNonNull(key, "key must not be null.");
		Objects.requireNonNull(data, "data must not be null.");

		this.key = key;
		this.data = data;
	}

	public byte[] getKey() {
		return key;
	}

	public byte[] getData() {
		return data;
	}
}