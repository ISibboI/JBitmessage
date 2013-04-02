package sibbo.bitmessage.protocol;

import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;
import java.util.logging.Logger;

import sibbo.bitmessage.data.InventoryObject;

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
	 * @param o The {@code InventoryObject} that should be hashed.
	 */
	public InventoryVectorMessage(InventoryObject o) {
		Objects.requireNonNull(o, "o must not be null!");

		hash = o.getHash();
	}

	/**
	 * {@link Message#Message(InputStream)}
	 */
	public InventoryVectorMessage(InputStream in) throws IOException,
			ParsingException {
		super(in);
	}

	public byte[] getHash() {
		return hash;
	}

	@Override
	protected void read(InputStream in) throws IOException, ParsingException {
		hash = new byte[32];
		readComplete(in, hash);
	}

	@Override
	public byte[] getBytes() {
		return hash;
	}
}