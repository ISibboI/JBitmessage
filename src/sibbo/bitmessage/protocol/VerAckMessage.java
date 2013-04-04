package sibbo.bitmessage.protocol;

import java.io.IOException;
import java.util.logging.Logger;

/**
 * Empty message for acknowledgment of a {@link VersionMessage}.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 * 
 */
public class VerAckMessage extends P2PMessage {
	private static final Logger LOG = Logger.getLogger(VerAckMessage.class
			.getName());

	/** The command string for this message type. */
	public static final String COMMAND = "verack";

	/**
	 * Creates a new verify and acknowledged message.
	 */
	public VerAckMessage() {
	}

	/**
	 * {@link Message#Message(InputBuffer)}
	 */
	public VerAckMessage(InputBuffer b) throws IOException, ParsingException {
		super(b);
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
