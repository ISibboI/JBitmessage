package sibbo.bitmessage.protocol;

import java.io.IOException;

/**
 * Used to identify actual messages that are identified by a command.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 * 
 */
public abstract class P2PMessage extends Message {
	/** The command string for this message type. */
	public static final String COMMAND = null;

	public P2PMessage() {
	}

	/**
	 * {@link Message#Message(InputBuffer)}
	 */
	public P2PMessage(InputBuffer b) throws IOException, ParsingException {
		super(b);
	}

	/**
	 * Returns the command string for this message type.
	 * 
	 * @return The command string for this message type.
	 */
	public abstract String getCommand();
}