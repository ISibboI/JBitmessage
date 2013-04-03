package sibbo.bitmessage.protocol;

import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;
import java.util.logging.Logger;

/**
 * A message containing the hash value of an inventory object.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 */
public class InventoryVectorMessage extends Message {
	private static final Logger LOG = Logger
			.getLogger(InventoryVectorMessage.class.getName());

	/** The hash */
	private byte[] hash; // 32

	/**
	 * Creates a new inventory vector message.
	 * 
	 * @param o The hash.
	 */
	public InventoryVectorMessage(byte[] hash) {
		Objects.requireNonNull(hash, "o must not be null!");

		if (hash.length != 32) {
			throw new IllegalArgumentException("hash must have a length of 32");
		}

		this.hash = hash;
	}

	/**
	 * {@link Message#Message(InputStream)}
	 */
	public InventoryVectorMessage(InputStream in, int maxLength)
			throws IOException, ParsingException {
		super(in, maxLength);
	}

	public byte[] getHash() {
		return hash;
	}

	@Override
	protected void read(InputStream in, int maxLength) throws IOException,
			ParsingException {
		hash = new byte[32];
		readComplete(in, hash);
	}

	@Override
	public byte[] getBytes() {
		return hash;
	}
}