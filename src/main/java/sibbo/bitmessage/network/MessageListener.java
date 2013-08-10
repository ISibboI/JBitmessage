package sibbo.bitmessage.network;

import sibbo.bitmessage.network.protocol.UnencryptedMessageDataMessage;

public interface MessageListener {
	/**
	 * A new message was received.
	 * 
	 * @param m The message.
	 */
	void messageReceived(UnencryptedMessageDataMessage m);
}