package sibbo.bitmessage.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.logging.Logger;

import sibbo.bitmessage.network.protocol.InputBuffer;
import sibbo.bitmessage.network.protocol.ParsingException;
import sibbo.bitmessage.network.protocol.VariableLengthIntegerListMessage;

public class VariableLengthIntegerListMessageTest {
	private static final Logger LOG = Logger
			.getLogger(VariableLengthIntegerListMessageTest.class.getName());

	public static void main(String[] args) throws IOException, ParsingException {
		long[] list = new long[] { -1, 0, 3, 0xfdffff, 1 };

		VariableLengthIntegerListMessage a = new VariableLengthIntegerListMessage(
				list);

		// System.out.println("Byteslength: " + a.getBytes().length);
		// System.out.print("Bytes:");
		//
		// for (byte x : a.getBytes()) {
		// System.out.print(" "
		// + Integer.toHexString(Util
		// .getInt(new byte[] { 0, 0, 0, x })));
		// }
		//
		// System.out.println();

		VariableLengthIntegerListMessage b = new VariableLengthIntegerListMessage(
				new InputBuffer(new ByteArrayInputStream(a.getBytes()),
						a.getBytes().length, a.getBytes().length));

		if (!Arrays.equals(list, b.getContent())) {
			System.out.println("Different lists: " + Arrays.toString(list)
					+ " != " + Arrays.toString(b.getContent()));
		}

		System.out.println("Finished");
	}
}
