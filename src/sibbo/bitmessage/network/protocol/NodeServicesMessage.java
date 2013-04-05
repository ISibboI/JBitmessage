package sibbo.bitmessage.network.protocol;

import java.io.IOException;
import java.util.Objects;
import java.util.logging.Logger;

/**
 * Contains constants for a bitfield describing the features of a node.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 */
public class NodeServicesMessage extends Message {
	private static final Logger LOG = Logger
			.getLogger(NodeServicesMessage.class.getName());

	public static final long NODE_NETWORK = 1;

	private long bitfield;

	/**
	 * Create a new node services message with the given flags.
	 * 
	 * @param flags The flags.
	 */
	public NodeServicesMessage(long... flags) {
		Objects.requireNonNull(flags, "flags must not be null.");

		bitfield = 0;

		for (long l : flags) {
			bitfield |= l;
		}
	}

	/**
	 * {@link Message#Message(InputBuffer)}
	 */
	public NodeServicesMessage(InputBuffer b) throws IOException,
			ParsingException {
		super(b);
	}

	@Override
	protected void read(InputBuffer b) throws IOException, ParsingException {
		bitfield = Util.getLong(b.get(0, 8));
	}

	@Override
	public byte[] getBytes() {
		return Util.getBytes(bitfield);
	}

	/**
	 * Returns true if all bits set in {@code flags} are also set for this
	 * bitfield.
	 * 
	 * @param nodeNetwork The flags to check.
	 * @return True if all given flags are set.
	 */
	public boolean isSet(long nodeNetwork) {
		return (nodeNetwork & bitfield) == nodeNetwork;
	}

	public int length() {
		return 8;
	}
}
