package sibbo.bitmessage.network.protocol;

import java.io.IOException;
import java.util.Objects;
import java.util.logging.Logger;

public class V1MessageFactory implements MessageFactory {
	private static final Logger LOG = Logger.getLogger(V1MessageFactory.class.getName());

	@Override
	public InventoryVectorMessage createInventoryVectorMessage(InputBuffer b) {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * Returns a new IGNORE message. The given data is probably ignored by the
	 * receiver.
	 * 
	 * @param data
	 *            Probably ignored by the receiver.
	 * @return A new ignore message.
	 */
	public MailMessage getIgnoreMailMessage(byte[] data) {
		Objects.requireNonNull(data, "data must not be null.");

		return new MailMessage(MessageEncoding.IGNORE, data, null, null, this);
	}

	/**
	 * Returns a new TRIVIAL message.
	 * 
	 * @param content
	 *            The message text.
	 * @return A new trivial message.
	 */
	public MailMessage getTrivialMailMessage(String content) {
		Objects.requireNonNull(content, "content must not be null.");

		return new MailMessage(MessageEncoding.TRIVIAL, null, null, content, this);
	}

	/**
	 * Returns a new SIMPLE message.
	 * 
	 * @param subject
	 *            The message subject.
	 * @param content
	 *            The message text.
	 * @return A new simple message.
	 */
	public MailMessage getSimpleMailMessage(String subject, String content) {
		Objects.requireNonNull(subject, "subject must not be null.");
		Objects.requireNonNull(content, "content must not be null.");

		return new MailMessage(MessageEncoding.SIMPLE, null, subject, content, this);
	}

	@Override
	public EncryptedMessage createEncryptedMessage(InputBuffer b) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public InventoryVectorMessage createInventoryVectorMessage(byte[] hash) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public NodeServicesMessage createNodeServicesMessage(InputBuffer b) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public BehaviorMessage createBehaviorMessage(InputBuffer b) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public MailMessage createMailMessage(InputBuffer b) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public VariableLengthIntegerMessage createVariableLengthIntegerMessage(InputBuffer b) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public VariableLengthIntegerMessage createVariableLengthIntegerMessage(long l) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public VersionMessage createVariableLengthStringMessage(String userAgent) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public VersionMessage createVariableLengthIntegerListMessage(long[] streams) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public VariableLengthIntegerListMessage createVariableLengthIntegerListMessage(InputBuffer b) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public VariableLengthStringMessage createVariableLengthStringMessage(InputBuffer b) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public SimpleNetworkAddressMessage createSimpleNetworkAddressMessage(InputBuffer b) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public NetworkAddressMessage createNetworkAddressMessage(InputBuffer b) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public BaseMessage createBaseMessage(InputBufferInputStream inputBufferInputStream, int length) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public P2PMessage createP2PMessage(String command, InputBuffer buffer) throws ParsingException, IOException {
		switch (command) {
		case VersionMessage.COMMAND:
			return new VersionMessage(buffer, this);
		case VerackMessage.COMMAND:
			return new VerackMessage(buffer, this);
		case AddrMessage.COMMAND:
			return new AddrMessage(buffer, this);
		case InvMessage.COMMAND:
			return new InvMessage(buffer, this);
		case GetdataMessage.COMMAND:
			return new GetdataMessage(buffer, this);
		case GetpubkeyMessage.COMMAND:
			return new GetpubkeyMessage(buffer, this);
		case PubkeyMessage.COMMAND:
			return new PubkeyMessage(buffer, this);
		case MsgMessage.COMMAND:
			return new MsgMessage(buffer, this);
		case UnencryptedBroadcastMessage.COMMAND:
			return new UnencryptedBroadcastMessage(buffer, this);
		default:
			throw new ParsingException("Unknown command: " + command);
		}
	}
}
