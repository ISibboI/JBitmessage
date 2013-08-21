package sibbo.bitmessage.network.protocol;

import java.io.IOException;

public interface MessageFactory {

	InventoryVectorMessage createInventoryVectorMessage(InputBuffer b);

	EncryptedMessage createEncryptedMessage(InputBuffer b);

	InventoryVectorMessage createInventoryVectorMessage(byte[] hash);

	NodeServicesMessage createNodeServicesMessage(InputBuffer b);

	BehaviorMessage createBehaviorMessage(InputBuffer b);

	MailMessage createMailMessage(InputBuffer b);

	VariableLengthIntegerMessage createVariableLengthIntegerMessage(InputBuffer b);

	VariableLengthIntegerMessage createVariableLengthIntegerMessage(long l);

	VersionMessage createVariableLengthStringMessage(String userAgent);

	VersionMessage createVariableLengthIntegerListMessage(long[] streams);

	VariableLengthIntegerListMessage createVariableLengthIntegerListMessage(InputBuffer b);

	VariableLengthStringMessage createVariableLengthStringMessage(InputBuffer b);

	SimpleNetworkAddressMessage createSimpleNetworkAddressMessage(InputBuffer b);

	NetworkAddressMessage createNetworkAddressMessage(InputBuffer b);

	BaseMessage createBaseMessage(InputBufferInputStream inputBufferInputStream, int length);

	P2PMessage createP2PMessage(String command, InputBuffer buffer) throws ParsingException, IOException;
}
