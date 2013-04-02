package sibbo.bitmessage.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.logging.Logger;

import sibbo.bitmessage.protocol.BaseMessage;
import sibbo.bitmessage.protocol.NetworkAddressMessage;
import sibbo.bitmessage.protocol.ParsingException;

public class BaseMessageTest {
	private static final Logger LOG = Logger.getLogger(BaseMessageTest.class
			.getName());

	public static void main(String[] args) throws IOException, ParsingException {
		byte[] magic = new byte[] { 4, -1, 0, 5 };
		String command = "Zero";
		NetworkAddressMessage m = new NetworkAddressMessage(1, 2, 3,
				InetAddress.getByName("4.5.6.7"), 8);

		BaseMessage b = new BaseMessage(magic, command, m);
		BaseMessage c = new BaseMessage(new ByteArrayInputStream(b.getBytes()));

		if (!Arrays.equals(c.getMagic(), magic)) {
			System.out.println("Wrong magic: " + Arrays.toString(c.getMagic())
					+ " != " + Arrays.toString(magic));
		}

		if (!c.getCommand().equals(command)) {
			System.out.println("Wrong command: " + c.getCommand() + " != "
					+ command);
		}

		if (!Arrays.equals(b.getPayload(), c.getPayload())) {
			System.out.println("The payloads are different: "
					+ Arrays.toString(c.getPayload()) + " != "
					+ Arrays.toString(b.getPayload()));
		}

		if (!Arrays.equals(m.getBytes(), c.getPayload())) {
			System.out
					.println("The resulting payload is not equal to the byte representation of the given message.");
		}

		System.out.println("Finished");
	}
}