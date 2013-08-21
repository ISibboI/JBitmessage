package sibbo.bitmessage.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.logging.Logger;

import sibbo.bitmessage.network.protocol.BaseMessage;
import sibbo.bitmessage.network.protocol.GetpubkeyMessage;
import sibbo.bitmessage.network.protocol.MessageFactory;
import sibbo.bitmessage.network.protocol.ParsingException;
import sibbo.bitmessage.network.protocol.V1MessageFactory;

public class GetpubkeyMessageTest {
	private static final Logger LOG = Logger.getLogger(GetpubkeyMessageTest.class.getName());

	public static void main(String[] args) throws IOException, ParsingException {
		MessageFactory factory = new V1MessageFactory();
		GetpubkeyMessage ap = new GetpubkeyMessage(1, 1, new byte[20], factory);
		BaseMessage a = new BaseMessage(ap, factory);

		ap.doPOW();
		byte[] ab = a.getBytes();

		BaseMessage b = new BaseMessage(new ByteArrayInputStream(ab), 10_000_000, factory);

		byte[] bb = b.getBytes();

		if (!Arrays.equals(ab, bb)) {
			System.out.println("Different: ");
			System.out.println(Arrays.toString(ab));
			System.out.println(Arrays.toString(bb));
		}
	}
}