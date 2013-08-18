package sibbo.bitmessage.test;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

import sibbo.bitmessage.network.protocol.Util;

import sun.misc.BASE64Decoder;

public class DestroyedMessage {
	private static final Logger LOG = Logger.getLogger(DestroyedMessage.class
			.getName());

	public static void main(String[] args) throws IOException {
		byte[] b = new BASE64Decoder().decodeBuffer(Files.newInputStream(FileSystems
				.getDefault().getPath("base64", new String[] {})));

		System.out.println(Arrays.toString(Arrays.copyOfRange(b,
				b.length - 200, b.length)));
		System.out.println(b.length);
		DecimalFormat df = new DecimalFormat("###,###,###,##0");

		byte[] time = new byte[] { 81, 94, -89, 92 };
		System.out.println("Time: " + df.format(Util.getInt(time)) + "/"
				+ df.format(System.currentTimeMillis() / 1000));

		int position = 0;

		List<Integer> magicValues = new ArrayList<>();

		for (int i = 0; i < b.length; i++) {
			if (position == 0 && b[i] == -23) {
				position = 1;
			} else if (position == 1 && b[i] == -66) {
				position = 2;
			} else if (position == 2 && b[i] == -76) {
				position = 3;
			} else if (position == 3 && b[i] == -39) {
				position = 4;
			} else if (position == 4) {
				position = 0;
				magicValues.add(i - 4);
			} else {
				position = 0;
			}
		}

		System.out.println("Found magic values: " + magicValues.size());
		for (Integer i : magicValues) {
			System.out.println("Magic value at: " + i);
		}
	}
}