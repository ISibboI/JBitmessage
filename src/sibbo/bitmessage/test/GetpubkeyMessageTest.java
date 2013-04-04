package sibbo.bitmessage.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.logging.Logger;

import sibbo.bitmessage.protocol.BaseMessage;
import sibbo.bitmessage.protocol.GetpubkeyMessage;
import sibbo.bitmessage.protocol.ParsingException;

public class GetpubkeyMessageTest {
	private static final Logger LOG = Logger
			.getLogger(GetpubkeyMessageTest.class.getName());

	public static void main(String[] args) throws IOException, ParsingException {
		GetpubkeyMessage ap = new GetpubkeyMessage(1, 1, new byte[20]);
		BaseMessage a = new BaseMessage(ap);

		ap.doPOW();
		byte[] ab = a.getBytes();

		BaseMessage b = new BaseMessage(new ByteArrayInputStream(ab),
				10_000_000);

		byte[] bb = b.getBytes();

		if (!Arrays.equals(ab, bb)) {
			System.out.println("Different: ");
			System.out.println(Arrays.toString(ab));
			System.out.println(Arrays.toString(bb));
		}
	}
}