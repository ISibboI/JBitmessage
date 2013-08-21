package sibbo.bitmessage.network.protocol;

import java.io.IOException;
import java.io.InputStream;

public interface MessageFactory {

	InventoryVectorMessage createInventoryVectorMessage(byte[] hash);

	VariableLengthIntegerListMessage createVariableLengthIntegerListMessage(long[] streams);

	VariableLengthIntegerMessage createVariableLengthIntegerMessage(long l);

	VariableLengthStringMessage createVariableLengthStringMessage(String userAgent);

	BaseMessage parseBaseMessage(InputStream in, int length) throws IOException, ParsingException;

	BehaviorMessage parseBehaviorMessage(InputBuffer b) throws IOException, ParsingException;

	EncryptedMessage parseEncryptedMessage(InputBuffer b) throws IOException, ParsingException;

	InventoryVectorMessage parseInventoryVectorMessage(InputBuffer b) throws IOException, ParsingException;

	MailMessage parseMailMessage(InputBuffer b) throws IOException, ParsingException;

	NetworkAddressMessage parseNetworkAddressMessage(InputBuffer b) throws IOException, ParsingException;

	NodeServicesMessage parseNodeServicesMessage(InputBuffer b) throws IOException, ParsingException;

	P2PMessage parseP2PMessage(String command, InputBuffer buffer) throws ParsingException, IOException;

	SimpleNetworkAddressMessage parseSimpleNetworkAddressMessage(InputBuffer b) throws IOException, ParsingException;

	VariableLengthIntegerListMessage parseVariableLengthIntegerListMessage(InputBuffer b) throws IOException,
			ParsingException;

	VariableLengthIntegerMessage parseVariableLengthIntegerMessage(InputBuffer b) throws IOException, ParsingException;

	VariableLengthStringMessage parseVariableLengthStringMessage(InputBuffer b) throws IOException, ParsingException;
}
