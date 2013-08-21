package sibbo.bitmessage.network.protocol;

import java.io.IOException;
import java.util.logging.Logger;

/**
 * Empty message for acknowledgment of a {@link VersionMessage}.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 * 
 */
public class VerackMessage extends P2PMessage {
	private static final Logger LOG = Logger.getLogger(VerackMessage.class.getName());

	/** The command string for this message type. */
	public static final String COMMAND = "verack";

	/**
	 * Creates a new verify and acknowledged message.
	 */
	public VerackMessage(MessageFactory factory) {
		super(factory);
	}

	/**
	 * {@link Message#Message(InputBuffer, MessageFactory)}
	 */
	public VerackMessage(InputBuffer b, MessageFactory factory) throws IOException, ParsingException {
		super(b, factory);
	}

	@Override
	protected void read(InputBuffer b) throws IOException, ParsingException {
	}

	@Override
	public byte[] getBytes() {
		return new byte[0];
	}

	public int length() {
		return 0;
	}

	@Override
	public String getCommand() {
		return COMMAND;
	}
}
