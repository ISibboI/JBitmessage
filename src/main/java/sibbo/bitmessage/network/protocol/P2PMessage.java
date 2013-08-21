package sibbo.bitmessage.network.protocol;

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

	/**
	 * {@link Message#Message(InputBuffer, MessageFactory)}
	 */
	public P2PMessage(MessageFactory factory) {
		super(factory);
	}

	/**
	 * {@link Message#Message(InputBuffer, MessageFactory)}
	 */
	public P2PMessage(InputBuffer b, MessageFactory factory) throws IOException, ParsingException {
		super(b, factory);
	}

	/**
	 * Returns the command string for this message type.
	 * 
	 * @return The command string for this message type.
	 */
	public abstract String getCommand();
}