package sibbo.bitmessage.network.protocol;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
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
	private static final Logger LOG = Logger.getLogger(VariableLengthIntegerListMessage.class.getName());

	private static final int MAX_LENGTH = 50_000;

	/** The list. */
	private long[] ints;

	/**
	 * Creates a new variable length integer list message with the given
	 * content.
	 * 
	 * @param ints
	 *            The numbers to store. Must not be longer than 50,000.
	 */
	public VariableLengthIntegerListMessage(long[] ints, MessageFactory factory) {
		super(factory);

		Objects.requireNonNull(ints, "ints must not be null.");

		if (ints.length > MAX_LENGTH) {
			throw new IllegalArgumentException("The maximum length for a variable length integer list is 50,000");
		}

		this.ints = ints;
	}

	/**
	 * {@link Message#Message(InputBuffer, MessageFactory)}
	 */
	public VariableLengthIntegerListMessage(InputBuffer b, MessageFactory factory) throws IOException, ParsingException {
		super(b, factory);
	}

	@Override
	protected void read(InputBuffer b) throws IOException, ParsingException {
		VariableLengthIntegerMessage length = getMessageFactory().parseVariableLengthIntegerMessage(b);
		b = b.getSubBuffer(length.length());
		long l = length.getLong();

		if (l > MAX_LENGTH || l < 0) {
			throw new ParsingException("List is to long. Maximum is 50,000");
		}

		ints = new long[(int) l];

		for (int i = 0; i < l; i++) {
			VariableLengthIntegerMessage v = getMessageFactory().parseVariableLengthIntegerMessage(b);
			b = b.getSubBuffer(v.length());
			ints[i] = v.getLong();
		}
	}

	@Override
	public byte[] getBytes() {
		VariableLengthIntegerMessage length = getMessageFactory().createVariableLengthIntegerMessage(ints.length);

		VariableLengthIntegerMessage[] varInts = new VariableLengthIntegerMessage[ints.length];

		for (int i = 0; i < ints.length; i++) {
			varInts[i] = getMessageFactory().createVariableLengthIntegerMessage(ints[i]);
		}

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
		return ints;
	}
}
