package sibbo.bitmessage.network;

import sibbo.bitmessage.network.protocol.UnencryptedMsgMessage;

public interface MessageListener {
	/**
	 * A new message was received.
	 * 
	 * @param m The message.
	 */
	void messageReceived(UnencryptedMsgMessage m);
}