package sibbo.bitmessage.protocol;

import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;

public abstract class Message {
	/**
	 * Creates a new empty NetworkMessage.
	 */
	protected Message() {
	}

	/**
	 * Creates a new message reading the data from the input stream.
	 * 
	 * @param in The input stream to read from.
	 * @throws IOException If reading from the given input stream fails.
	 * @throws ParsingException If parsing the data fails.
	 */
	public Message(InputStream in) throws IOException, ParsingException {
		Objects.requireNonNull(in, "in must not be null!");

		read(in);
	}

	/**
	 * Initializes the message reading the data from the input stream.
	 * 
	 * @param in The input stream to read from.
	 * @throws IOException If reading from the given input stream fails.
	 * @throws ParsingException If parsing the data fails.
	 */
	protected abstract void read(InputStream in) throws IOException,
			ParsingException;

	/**
	 * Creates a byte array of containing this message.
	 * 
	 * @return A byte array of containing this message.
	 */
	public abstract byte[] getBytes();

	/**
	 * Ensures that the given byte array is completely filled with bytes from
	 * the input stream. If that's not possible, an IOException is thrown.
	 * 
	 * @param in The input stream to read from.
	 * @param b The byte array to fill.
	 * @throws IOException If the byte array could not be filled.
	 */
	protected void readComplete(InputStream in, byte[] b) throws IOException {
		int offset = 0;

		while (offset < b.length) {
			int length = in.read(b, offset, b.length - offset);

			if (length == -1) {
				throw new IOException("End of stream.");
			} else {
				offset += length;
			}
		}
	}
}