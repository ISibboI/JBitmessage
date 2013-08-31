package sibbo.bitmessage.network;

import java.util.logging.Logger;

/**
 * Contains utility functions for streams.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 */
public final class Streams {
	private static final Logger LOG = Logger.getLogger(Streams.class.getName());

	/** Utility class. */
	private Streams() {
	}

	/**
	 * Returns an array containing the given stream and its parent and child
	 * streams.
	 * 
	 * @param stream
	 *            A stream.
	 * @return The perimeter of the given stream.
	 */
	public static long[] getPerimeter(long stream) {
		if (stream <= 0) {
			throw new IllegalArgumentException("stream must not be <= 0.");
		}

		if (stream == 1) {
			// Don't insert 0.
			return new long[] { stream, 2 * stream, 2 * stream + 1 };
		} else {
			return new long[] { stream / 2, stream, 2 * stream, 2 * stream + 1 };
		}
	}

	/**
	 * Returns a long[] containing a path from startStream to targetStream.
	 * 
	 * @param startStream
	 *            The start stream.
	 * @param targetStream
	 *            The target stream.
	 * @return A long[] containing a path from startStream to targetStream.
	 */
	public static long[] getPath(long startStream, long targetStream) {
		if (startStream <= 0) {
			throw new IllegalArgumentException("startStream must not be <= 0.");
		}

		if (targetStream <= 0) {
			throw new IllegalArgumentException("targetStream must not be <= 0.");
		}

		String start = Long.toBinaryString(startStream);
		String target = Long.toBinaryString(targetStream);
		int prefix = 0;

		for (int i = 0; i < start.length() && i < target.length(); i++) {
			if (start.charAt(i) == target.charAt(i)) {
				prefix++;
			} else {
				break;
			}
		}

		start = start.substring(prefix);
		target = target.substring(prefix);

		long[] path = new long[start.length() + target.length() + 1];
		path[0] = startStream;
		int index = 1;

		for (int i = 0; i < start.length(); i++) {
			path[index] = path[index - 1] / 2;
			index++;
		}

		for (char c : target.toCharArray()) {
			if (c == '1') {
				path[index] = (path[index - 1] << 1) + 1;
			} else {
				path[index] = path[index - 1] << 1;
			}

			index++;
		}

		return path;
	}
}