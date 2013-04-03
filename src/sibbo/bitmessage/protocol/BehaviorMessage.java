package sibbo.bitmessage.protocol;

import java.io.IOException;
import java.io.InputStream;
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
	private static final Logger LOG = Logger.getLogger(BehaviorMessage.class
			.getName());

	public static final int DOES_ACK = 1;

	/** Storing the behavior-flags. */
	private int bitfield;

	/**
	 * Creates a new behavior message with the given flags.
	 * 
	 * @param flags The flags.
	 */
	public BehaviorMessage(int... flags) {
		Objects.requireNonNull(flags, "flags must not be null.");

		bitfield = 0;

		for (int i : flags) {
			bitfield |= i;
		}
	}

	/**
	 * @link {@link Message#Message(InputStream)}
	 */
	public BehaviorMessage(InputStream in, int maxLength) throws IOException,
			ParsingException {
		super(in, maxLength);
	}

	@Override
	protected void read(InputStream in, int maxLength) throws IOException,
			ParsingException {
		byte[] bits = new byte[4];
		readComplete(in, bits);
		bitfield = Util.getInt(bits);
	}

	@Override
	public byte[] getBytes() {
		return Util.getBytes(bitfield);
	}

	/**
	 * Returns true if all bits set in {@code flags} are also set for this
	 * bitfield.
	 * 
	 * @param flags The flags to check.
	 * @return True if all given flags are set.
	 */
	public boolean isSet(int flags) {
		return (flags & bitfield) == flags;
	}
}
