package sibbo.bitmessage.network.protocol;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A message containing a string with variable length.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 * 
 */
public class VariableLengthStringMessage extends Message {
	private static final Logger LOG = Logger.getLogger(VariableLengthStringMessage.class.getName());

	private static final int MAX_LENGTH = 50_000;

	/** The string. */
	private String message;

	/**
	 * Creates a new variable length string message with the given string.
	 * 
	 * @param message
	 *            The string.
	 */
	public VariableLengthStringMessage(String message, MessageFactory factory) {
		super(factory);

		Objects.requireNonNull(message, "message must not be null.");

		try {
			if (message.getBytes("UTF-8").length > MAX_LENGTH) {
				throw new IllegalArgumentException("String is too long. Maximum length is " + MAX_LENGTH);
			}
		} catch (UnsupportedEncodingException e) {
			LOG.log(Level.SEVERE, "UTF-8 not supported!", e);
			System.exit(1);
		}

		this.message = message;
	}

	/**
	 * {@link Message#Message(InputBuffer,MessageFactory)}
	 */
	public VariableLengthStringMessage(InputBuffer b, MessageFactory factory) throws IOException, ParsingException {
		super(b, factory);
	}

	@Override
	protected void read(InputBuffer b) throws IOException, ParsingException {
		VariableLengthIntegerMessage vLength = getMessageFactory().parseVariableLengthIntegerMessage(b);
		b = b.getSubBuffer(vLength.length());
		long length = vLength.getLong();

		if (length > MAX_LENGTH || length < 0) {
			throw new ParsingException("String is too long. Maximum length is " + MAX_LENGTH);
		}

		byte[] bytes = b.get(0, (int) length);

		try {
			message = new String(bytes, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			LOG.log(Level.SEVERE, "UTF-8 not supported!", e);
			System.exit(1);
		}
	}

	@Override
	public byte[] getBytes() {
		ByteArrayOutputStream b = new ByteArrayOutputStream();

		try {
			byte[] bytes = message.getBytes("UTF-8");

			b.write(getMessageFactory().createVariableLengthIntegerMessage(bytes.length).getBytes());
			b.write(bytes);
		} catch (UnsupportedEncodingException e) {
			LOG.log(Level.SEVERE, "UTF-8 not supported!", e);
			System.exit(1);
		} catch (IOException e) {
			LOG.log(Level.SEVERE, "Could not write bytes!", e);
			System.exit(1);
		}

		return b.toByteArray();
	}

	public String getMessage() {
		return message;
	}

	public int length() {
		try {
			byte[] bytes = message.getBytes("UTF-8");

			return getMessageFactory().createVariableLengthIntegerMessage(bytes.length).length() + bytes.length;
		} catch (UnsupportedEncodingException e) {
			LOG.log(Level.SEVERE, "UTF-8 not supported!", e);
			System.exit(1);
			return 0;
		}
	}
}