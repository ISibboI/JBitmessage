package sibbo.bitmessage.protocol;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.logging.Logger;

/**
 * A data structure that reads from an input stream and buffers all data. The
 * data can't be manipulated, but substructures can be created. All
 * substructures share the underlying buffer.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 * 
 */
public class InputBuffer {
	private static final Logger LOG = Logger.getLogger(InputBuffer.class
			.getName());
	private Buffer buffer;

	private int offset = 0;
	private int length;

	/**
	 * Creates a new InputBuffer reading from the given input stream. The buffer
	 * is limited to maxSize.
	 * 
	 * @param in The input stream to read from.
	 * @param chunkSize The minimum size of data to request from {@code in}
	 * @param maxSize The maximum size of the buffer.
	 */
	public InputBuffer(InputStream in, int chunkSize, int maxSize) {
		buffer = new Buffer(in, chunkSize, maxSize);
		length = maxSize;
	}

	private InputBuffer(Buffer buffer, int offset, int length) {
		this.buffer = buffer;
		this.offset = offset;
		this.length = length;
	}

	/**
	 * Returns the byte at the specified index. If the byte has not yet been
	 * read, this method blocks until it is read or an error occurs.
	 * 
	 * @param index The index of the byte to read.
	 * @return A byte.
	 * @throws IOException If the byte at {@code index} could not be read.
	 */
	public byte get(int index) throws IOException {
		if (index < 0 || index >= length) {
			throw new IndexOutOfBoundsException("Out of bounds: " + index + "/"
					+ length);
		}

		return buffer.get(offset + index);
	}

	/**
	 * Returns a byte array containing the bytes in the specified range. If the
	 * bytes have not yet been read, this method blocks until they are read or
	 * an error occurs.
	 * 
	 * @param offset The start of the range to copy.
	 * @param length The length of the range to copy.
	 * @return A byte array.
	 * @throws IOException If the bytes in the specified range could not be
	 *             read.
	 */
	public byte[] get(int offset, int length) throws IOException {
		if (offset < 0 || offset + length >= this.offset + this.length) {
			throw new IndexOutOfBoundsException("Out of bounds: " + offset
					+ "-" + length + "/" + this.offset + "-" + length);
		}

		return buffer.get(offset + this.offset, length);
	}

	/**
	 * Creates a new input buffer that maps it's requests to the given range of
	 * this buffer.<br />
	 * <br />
	 * That means if:<br />
	 * <code>InputBuffer a = new InputBuffer(...);<br />
	 * InputBuffer b = a.getSubBuffer(5, 5);</code><br />
	 * <br />
	 * Then:<br />
	 * <code>a.get(i+5) == b.get(i)</code><br />
	 * For i element {0, 1, 2, 3, 4}.
	 * 
	 * @param offset The offset of the new buffer.
	 * @param length The length of the new buffer.
	 * @return A sub buffer of this one.
	 */
	public InputBuffer getSubBuffer(int offset, int length) {
		if (offset < 0 || offset + length >= this.offset + this.length) {
			throw new IndexOutOfBoundsException("Out of bounds: " + offset
					+ "-" + length + "/" + this.offset + "-" + length);
		}

		return new InputBuffer(buffer, offset + this.offset, length);
	}

	/**
	 * Creates a new input buffer that maps it's requests to the given range of
	 * this buffer.<br />
	 * <br />
	 * That means if:<br />
	 * <code>InputBuffer a = new InputBuffer(in, x, 10);<br />
	 * int offset = 5;<br />
	 * InputBuffer b = a.getSubBuffer(offset);</code><br />
	 * <br />
	 * Then:<br />
	 * <code>a.get(i+5) == b.get(i)</code><br />
	 * For i element {0, 1, 2, 3, 4}.<br />
	 * <br />
	 * The length of the new buffer is:<br />
	 * <code>a.length() - offset</code>
	 * 
	 * @param offset The offset of the new buffer.
	 * @return A sub buffer of this one.
	 */
	public InputBuffer getSubBuffer(int offset) {
		if (offset < 0 || offset > length) {
			throw new IndexOutOfBoundsException("Out of bounds: " + offset
					+ "/" + length);
		}

		return new InputBuffer(buffer, offset + this.offset, length - offset);
	}

	/**
	 * Returns the length of this buffer.
	 * 
	 * @return The length of this buffer.
	 */
	public int length() {
		return length;
	}

	private class Buffer {
		private InputStream in;
		private int size;
		private List<byte[]> buffer;
		private int maxSize;
		private int chunkSize;

		public Buffer(InputStream in, int chunkSize, int maxSize) {
			Objects.requireNonNull(in, "in must not be null.");

			this.in = in;
			this.maxSize = maxSize;
			this.chunkSize = chunkSize;

			buffer = new ArrayList<>(maxSize / chunkSize + 1);
		}

		public byte get(int index) throws IOException {
			if (index < 0 || index >= maxSize) {
				throw new IndexOutOfBoundsException("Index out of bounds: "
						+ index);
			}

			if (index >= size) {
				read(index);
			}

			return buffer.get(index / chunkSize)[index % chunkSize];
		}

		public byte[] get(int offset, int length) throws IOException {
			if (offset < 0 || offset >= maxSize) {
				throw new IndexOutOfBoundsException("Offset out of bounds: "
						+ offset);
			}

			if (length < 0) {
				throw new IndexOutOfBoundsException("Length negative: "
						+ length);
			}

			if (offset + length > maxSize) {
				throw new IndexOutOfBoundsException(
						"Length + Offset out of bounds: " + (length + offset));
			}

			if (offset + length > size) {
				read(offset + length);
			}

			byte[] b = new byte[length];
			int index = 0;
			int chunkOffset = offset;

			for (int i = offset / chunkSize; i <= (offset + length - 1)
					/ chunkSize; i++) {
				int cl = (i + 1) * chunkSize - chunkOffset;

				if (cl > offset + length - chunkOffset) {
					cl = offset + length - chunkOffset;
				}

				copy(buffer.get(i), b, chunkOffset % chunkSize, index, cl);

				index += cl;
				chunkOffset += cl;
			}

			return b;
		}

		private void copy(byte[] source, byte[] target, int sourceOffset,
				int targetOffset, int length) {
			int delta = targetOffset - sourceOffset;
			for (int i = sourceOffset; i < sourceOffset + length; i++) {
				target[delta + i] = source[i];
			}
		}

		private void read(int index) throws IOException {
			int firstChunk = buffer.size();
			int lastChunk = index / chunkSize;

			for (int i = firstChunk; i <= lastChunk; i++) {
				int chunkSize = this.chunkSize;

				if ((i + 1) * chunkSize > maxSize) {
					chunkSize = maxSize % chunkSize;
				}

				byte[] b = new byte[chunkSize];
				readComplete(in, b);
				buffer.add(b);
			}

			size = (lastChunk * chunkSize) + chunkSize;
		}

		/**
		 * Ensures that the given byte array is completely filled with bytes
		 * from the input stream. If that's not possible, an IOException is
		 * thrown.
		 * 
		 * @param in The input stream to read from.
		 * @param b The byte array to fill.
		 * @throws IOException If the byte array could not be filled.
		 */
		protected void readComplete(InputStream in, byte[] b)
				throws IOException {
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

	// public static void main(String[] args) throws IOException {
	// byte[] source = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
	// 13, 14, 15, 16, 17, 18, 19 };
	//
	// NetworkInputBuffer x = new NetworkInputBuffer();
	// Buffer b = x.new Buffer(new ByteArrayInputStream(source), 250, 20);
	//
	// for (int i = 0; i < source.length; i++) {
	// if (source[i] != b.get(i)) {
	// System.out.println("Index " + i + ": source[i] == " + source[i]
	// + " != " + b.get(i) + " == b.get(i)");
	// }
	// }
	//
	// if (!Arrays.equals(source, b.get(0, 20))) {
	// System.out.println(Arrays.toString(source) + " != "
	// + Arrays.toString(b.get(0, 20)));
	// }
	//
	// byte[] a;
	// byte[] c;
	//
	// int offset = 16;
	// int length = 4;
	// a = Arrays.copyOfRange(source, offset, offset + length);
	// c = b.get(offset, length);
	// if (!Arrays.equals(a, c)) {
	// System.out
	// .println(Arrays.toString(a) + " != " + Arrays.toString(c));
	// }
	// }
}