package sibbo.bitmessage.protocol;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A message containing a list of integers.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 */
public class VariableLengthIntegerListMessage extends Message {
	private static final Logger LOG = Logger
			.getLogger(VariableLengthIntegerListMessage.class.getName());

	private static final int MAX_LENGTH = 50_000;

	/** The number of entries in the list. */
	private VariableLengthIntegerMessage length;

	/** The entries. */
	private VariableLengthIntegerMessage[] varInts;

	/**
	 * Creates a new variable length integer list message with the given
	 * content.
	 * 
	 * @param ints The numbers to store. Must not be longer than 50,000.
	 */
	public VariableLengthIntegerListMessage(long[] ints) {
		Objects.requireNonNull(ints, "ints must not be null.");

		if (ints.length > MAX_LENGTH) {
			throw new IllegalArgumentException(
					"The maximum length for a variable length integer list is 50,000");
		}

		length = new VariableLengthIntegerMessage(ints.length);

		varInts = new VariableLengthIntegerMessage[ints.length];

		for (int i = 0; i < ints.length; i++) {
			varInts[i] = new VariableLengthIntegerMessage(ints[i]);
		}
	}

	/**
	 * {@link Message#Message(InputStream)}
	 */
	public VariableLengthIntegerListMessage(InputStream in) throws IOException,
			ParsingException {
		super(in);
	}

	@Override
	protected void read(InputStream in) throws IOException, ParsingException {
		length = new VariableLengthIntegerMessage(in);
		long l = length.getLong();

		if (l > MAX_LENGTH) {
			throw new ParsingException("List is to long. Maximum is 50,000");
		}

		varInts = new VariableLengthIntegerMessage[(int) l];

		for (int i = 0; i < l; i++) {
			varInts[i] = new VariableLengthIntegerMessage(in);
		}
	}

	@Override
	public byte[] getBytes() {
		ByteArrayOutputStream b = new ByteArrayOutputStream();

		try {
			b.write(length.getBytes());

			for (VariableLengthIntegerMessage l : varInts) {
				b.write(l.getBytes());
			}
		} catch (IOException e) {
			LOG.log(Level.SEVERE, "Could not write bytes!", e);
			System.exit(1);
		}

		return b.toByteArray();
	}

	/**
	 * Returns the content of the list as long[].
	 * 
	 * @return The content of the list as long[].
	 */
	public long[] getContent() {
		long[] l = new long[(int) length.getLong()];

		for (int i = 0; i < l.length; i++) {
			l[i] = varInts[i].getLong();
		}

		return l;
	}
}
