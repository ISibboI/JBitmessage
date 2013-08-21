package sibbo.bitmessage.network.protocol;

import java.io.IOException;
import java.util.Objects;
import java.util.logging.Logger;

/**
 * A message containing a bitfield that informs about the behavior of a node
 * when receiving with a specific address.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 */
public class BehaviorMessage extends Message {
	private static final Logger LOG = Logger.getLogger(BehaviorMessage.class.getName());

	/** The node sends acknowledgments. */
	public static final int DOES_ACK = 1;

	/**
	 * The node includes the destination ripe inside of a msg message. (Not
	 * specified how, DON'T USE!)
	 */
	public static final int INCLUDE_DESTINATION = 2;

	/** Storing the behavior-flags. */
	private int bitfield;

	/**
	 * Creates a new behavior message with the given flags.
	 * 
	 * @param flags
	 *            The flags.
	 */
	public BehaviorMessage(MessageFactory factory, int... flags) {
		super(factory);

		Objects.requireNonNull(flags, "flags must not be null.");

		bitfield = 0;

		for (int i : flags) {
			bitfield |= i;
		}
	}

	/**
	 * @link {@link Message#Message(InputBuffer, MessageFactory)}
	 */
	public BehaviorMessage(InputBuffer b, MessageFactory factory) throws IOException, ParsingException {
		super(b, factory);
	}

	@Override
	protected void read(InputBuffer b) throws IOException, ParsingException {
		bitfield = Util.getInt(b.get(0, 4));
	}

	@Override
	public byte[] getBytes() {
		return Util.getBytes(bitfield);
	}

	/**
	 * Returns true if all bits set in {@code flags} are also set for this
	 * bitfield.
	 * 
	 * @param flags
	 *            The flags to check.
	 * @return True if all given flags are set.
	 */
	public boolean isSet(int flags) {
		return (flags & bitfield) == flags;
	}

	public int length() {
		return 4;
	}
}
