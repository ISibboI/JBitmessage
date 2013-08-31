package sibbo.bitmessage.network.protocol;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.util.Collection;

import org.bouncycastle.jce.interfaces.ECPublicKey;

public abstract class MessageFactory {
	/**
	 * Creates a new message factory that implements the given protocol version.
	 * 
	 * @param version
	 *            The protocol version.
	 * @return A message factory creating objects fitting to the given protocol
	 *         version.
	 */
	public static final MessageFactory getFactoryByVersion(int version) {
		switch (version) {
		case 1:
			return new V1MessageFactory();
		default:
			return null;
		}
	}

	public abstract AddrMessage createAddrMessage(Collection<NetworkAddressMessage> addresses);

	public abstract BaseMessage createBaseMessage(P2PMessage message);

	public abstract EncryptedMessage createEncryptedMessage(byte[] iv, ECPublicKey key, byte[] encrypted, byte[] mac);

	public abstract GetdataMessage createGetdataMessage(Collection<InventoryVectorMessage> inv);

	public abstract InventoryVectorMessage createInventoryVectorMessage(byte[] hash);

	public abstract InvMessage createInvMessage(Collection<InventoryVectorMessage> inv);

	public abstract NodeServicesMessage createNodeServicesMessage(long services);

	public abstract SimpleNetworkAddressMessage createSimpleNetworkAddressMessage(NodeServicesMessage services,
			InetAddress address, int port);

	public abstract VariableLengthIntegerListMessage createVariableLengthIntegerListMessage(long[] streams);

	public abstract VariableLengthIntegerMessage createVariableLengthIntegerMessage(long l);

	public abstract VariableLengthStringMessage createVariableLengthStringMessage(String userAgent);

	public abstract VerackMessage createVerackMessage();

	public abstract VersionMessage createVersionMessage(NodeServicesMessage services, long time,
			SimpleNetworkAddressMessage receiver, SimpleNetworkAddressMessage sender, long nonce, String userAgent,
			long[] streams);

	public abstract BaseMessage parseBaseMessage(InputStream in, int length) throws IOException, ParsingException;

	public abstract BehaviorMessage parseBehaviorMessage(InputBuffer b) throws IOException, ParsingException;

	public abstract EncryptedMessage parseEncryptedMessage(InputBuffer b) throws IOException, ParsingException;

	public abstract InventoryVectorMessage parseInventoryVectorMessage(InputBuffer b) throws IOException,
			ParsingException;

	public abstract MailMessage parseMailMessage(InputBuffer b) throws IOException, ParsingException;

	public abstract NetworkAddressMessage parseNetworkAddressMessage(InputBuffer b) throws IOException,
			ParsingException;

	public abstract NodeServicesMessage parseNodeServicesMessage(InputBuffer b) throws IOException, ParsingException;

	public abstract P2PMessage parseP2PMessage(String command, InputBuffer buffer) throws ParsingException, IOException;

	public abstract SimpleNetworkAddressMessage parseSimpleNetworkAddressMessage(InputBuffer b) throws IOException,
			ParsingException;

	public abstract UnencryptedMsgMessage parseUnencryptedMsgMessage(InputBuffer b) throws IOException,
			ParsingException;

	public abstract VariableLengthIntegerListMessage parseVariableLengthIntegerListMessage(InputBuffer b)
			throws IOException, ParsingException;

	public abstract VariableLengthIntegerMessage parseVariableLengthIntegerMessage(InputBuffer b) throws IOException,
			ParsingException;

	public abstract VariableLengthStringMessage parseVariableLengthStringMessage(InputBuffer b) throws IOException,
			ParsingException;
}
