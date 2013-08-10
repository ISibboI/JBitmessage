package sibbo.bitmessage.network.protocol;

import java.io.IOException;
import java.io.InputStream;
import java.util.logging.Logger;

/**
 * An input stream that reads from an {@link InputBuffer}.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 * 
 */
public class InputBufferInputStream extends InputStream {
	private static final Logger LOG = Logger
			.getLogger(InputBufferInputStream.class.getName());

	private InputBuffer buffer;
	private int index;

	public InputBufferInputStream(InputBuffer buffer) {
		this.buffer = buffer;
		index = 0;
	}

	@Override
	public int read() throws IOException {
		if (index >= buffer.length()) {
			return -1;
		} else {
			return buffer.get(index++);
		}
	}

	@Override
	public int read(byte[] b) throws IOException {
		return read(b, 0, b.length);
	}

	@Override
	public int read(byte[] b, int offset, int length) throws IOException {
		if (offset < 0) {
			throw new IndexOutOfBoundsException("Offset must be > 0.");
		}

		if (length < 0) {
			throw new IndexOutOfBoundsException("Length must be > 0.");
		}

		if (offset + length >= b.length) {
			throw new IndexOutOfBoundsException(
					"Offset + length must be < b.length.");
		}

		if (index >= buffer.length()) {
			return -1;
		}

		if (length > buffer.length() - index) {
			length = buffer.length() - index;
		}

		byte[] a = buffer.get(index, length);

		for (int i = offset; i < offset + length; i++) {
			b[i] = a[i - index];
		}

		index += length;
		return length;
	}
}