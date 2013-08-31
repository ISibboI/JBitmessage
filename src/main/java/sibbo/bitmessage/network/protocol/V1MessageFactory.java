package sibbo.bitmessage.network.protocol;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.util.Collection;
import java.util.Objects;
import java.util.logging.Logger;

import org.bouncycastle.jce.interfaces.ECPublicKey;

public class V1MessageFactory extends MessageFactory {
	private static final Logger LOG = Logger.getLogger(V1MessageFactory.class.getName());

	@Override
	public AddrMessage createAddrMessage(Collection<NetworkAddressMessage> addresses) {
		return new AddrMessage(addresses, this);
	}

	@Override
	public BaseMessage createBaseMessage(P2PMessage message) {
		return new BaseMessage(message, this);
	}

	@Override
	public EncryptedMessage createEncryptedMessage(byte[] iv, ECPublicKey key, byte[] encrypted, byte[] mac) {
		return new EncryptedMessage(iv, key, encrypted, mac, this);
	}

	@Override
	public GetdataMessage createGetdataMessage(Collection<InventoryVectorMessage> inv) {
		return new GetdataMessage(inv, this);
	}

	@Override
	public InventoryVectorMessage createInventoryVectorMessage(byte[] hash) {
		return new InventoryVectorMessage(hash, this);
	}

	@Override
	public InvMessage createInvMessage(Collection<InventoryVectorMessage> inv) {
		return new InvMessage(inv, this);
	}

	@Override
	public NodeServicesMessage createNodeServicesMessage(long services) {
		return new NodeServicesMessage(this, services);
	}

	@Override
	public SimpleNetworkAddressMessage createSimpleNetworkAddressMessage(NodeServicesMessage services,
			InetAddress address, int port) {
		return new SimpleNetworkAddressMessage(services, address, port, this);
	}

	@Override
	public VariableLengthIntegerListMessage createVariableLengthIntegerListMessage(long[] streams) {
		return new VariableLengthIntegerListMessage(streams, this);
	}

	@Override
	public VariableLengthIntegerMessage createVariableLengthIntegerMessage(long l) {
		return new VariableLengthIntegerMessage(l, this);
	}

	@Override
	public VariableLengthStringMessage createVariableLengthStringMessage(String userAgent) {
		return new VariableLengthStringMessage(userAgent, this);
	}

	@Override
	public VerackMessage createVerackMessage() {
		return new VerackMessage(this);
	}

	@Override
	public VersionMessage createVersionMessage(NodeServicesMessage services, long time,
			SimpleNetworkAddressMessage receiver, SimpleNetworkAddressMessage sender, long nonce, String userAgent,
			long[] streams) {
		return new VersionMessage(services, time, receiver, sender, nonce, userAgent, streams, this);
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

	@Override
	public BaseMessage parseBaseMessage(InputStream in, int length) throws IOException, ParsingException {
		return new BaseMessage(in, length, this);
	}

	@Override
	public BehaviorMessage parseBehaviorMessage(InputBuffer b) throws IOException, ParsingException {
		return new BehaviorMessage(b, this);
	}

	@Override
	public EncryptedMessage parseEncryptedMessage(InputBuffer b) throws IOException, ParsingException {
		return new EncryptedMessage(b, this);
	}

	@Override
	public InventoryVectorMessage parseInventoryVectorMessage(InputBuffer b) throws IOException, ParsingException {
		return new InventoryVectorMessage(b, this);
	}

	@Override
	public MailMessage parseMailMessage(InputBuffer b) throws IOException, ParsingException {
		return new MailMessage(b, this);
	}

	@Override
	public NetworkAddressMessage parseNetworkAddressMessage(InputBuffer b) throws IOException, ParsingException {
		return new NetworkAddressMessage(b, this);
	}

	@Override
	public NodeServicesMessage parseNodeServicesMessage(InputBuffer b) throws IOException, ParsingException {
		return new NodeServicesMessage(b, this);
	}

	@Override
	public P2PMessage parseP2PMessage(String command, InputBuffer buffer) throws ParsingException, IOException {
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

	@Override
	public SimpleNetworkAddressMessage parseSimpleNetworkAddressMessage(InputBuffer b) throws IOException,
			ParsingException {
		return new SimpleNetworkAddressMessage(b, this);
	}

	@Override
	public UnencryptedMsgMessage parseUnencryptedMsgMessage(InputBuffer b) throws IOException, ParsingException {
		return new UnencryptedMsgMessage(b, this);
	}

	@Override
	public VariableLengthIntegerListMessage parseVariableLengthIntegerListMessage(InputBuffer b) throws IOException,
			ParsingException {
		return new VariableLengthIntegerListMessage(b, this);
	}

	@Override
	public VariableLengthIntegerMessage parseVariableLengthIntegerMessage(InputBuffer b) throws IOException,
			ParsingException {
		return new VariableLengthIntegerMessage(b, this);
	}

	@Override
	public VariableLengthStringMessage parseVariableLengthStringMessage(InputBuffer b) throws IOException,
			ParsingException {
		return new VariableLengthStringMessage(b, this);
	}
}
