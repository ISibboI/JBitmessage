package sibbo.bitmessage.protocol;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Represents a mail.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 */
public class MailMessage extends Message {
	private static final Logger LOG = Logger.getLogger(MailMessage.class
			.getName());

	/** The encoding of this mail. */
	private MessageEncoding encoding;

	/**
	 * Contains the byte data of the subject and content, depending on the
	 * encoding.
	 */
	private byte[] data;

	/** The subject of a message. Is not used by all encodings. */
	private String subject;

	/** The content of a message. Is not used by all encodings. */
	private String content;

	private MailMessage(MessageEncoding encoding, byte[] data, String subject,
			String content) {
		this.encoding = encoding;

		this.data = data;
		this.subject = subject;
		this.content = content;
	}

	/**
	 * {@link Message#Message(InputBuffer)}
	 */
	public MailMessage(InputBuffer b) throws IOException, ParsingException {
		super(b);
	}

	/**
	 * Returns a new IGNORE message. The given data is probably ignored by the
	 * receiver.
	 * 
	 * @param data Probably ignored by the receiver.
	 * @return A new ignore message.
	 */
	public static MailMessage getIgnoreMessage(byte[] data) {
		Objects.requireNonNull(data, "data must not be null.");

		return new MailMessage(MessageEncoding.IGNORE, data, null, null);
	}

	/**
	 * Returns a new TRIVIAL message.
	 * 
	 * @param content The message text.
	 * @return A new trivial message.
	 */
	public static MailMessage getTrivialMessage(String content) {
		Objects.requireNonNull(content, "content must not be null.");

		return new MailMessage(MessageEncoding.IGNORE, null, null, content);
	}

	/**
	 * Returns a new SIMPLE message.
	 * 
	 * @param subject The message subject.
	 * @param content The message text.
	 * @return A new simple message.
	 */
	public static MailMessage getSimpleMessage(String subject, String content) {
		Objects.requireNonNull(subject, "subject must not be null.");
		Objects.requireNonNull(content, "content must not be null.");

		return new MailMessage(MessageEncoding.IGNORE, null, subject, content);
	}

	public MessageEncoding getEncoding() {
		return encoding;
	}

	public byte[] getData() {
		return data;
	}

	public String getSubject() {
		return subject;
	}

	public String getContent() {
		return content;
	}

	@Override
	protected void read(InputBuffer b) throws IOException, ParsingException {
		VariableLengthIntegerMessage i = new VariableLengthIntegerMessage(b);
		b = b.getSubBuffer(i.length());
		encoding = MessageEncoding.getEncoding(i.getLong());

		i = new VariableLengthIntegerMessage(b);
		b = b.getSubBuffer(i.length());
		long length = i.getLong();

		if (length > b.length() || length < 0) {
			throw new ParsingException("Message too long: " + length);
		}

		data = b.get(0, (int) length);

		switch (encoding) {
			case IGNORE:
				break;

			case TRIVIAL:
				content = new String(data, "UTF-8");
				break;

			case SIMPLE:
				String s = new String(data, "UTF-8").substring(8);
				int index = s.indexOf("\nBody:");

				subject = s.substring(0, index);
				content = s.substring(index + 6);
				break;

			default:
				throw new ParsingException("Unknown encoding: " + encoding);
		}
	}

	@Override
	public byte[] getBytes() {
		ByteArrayOutputStream b = new ByteArrayOutputStream();

		try {
			b.write(new VariableLengthIntegerMessage(encoding.getConstant())
					.getBytes());

			switch (encoding) {
				case IGNORE:
					break;

				case TRIVIAL:
					data = content.getBytes("UTF-8");
					break;

				case SIMPLE:
					data = ("Subject:" + subject + "\nBody:" + content)
							.getBytes();
					break;

				default:
					LOG.log(Level.SEVERE, "Unknown encoding: " + encoding);
					System.exit(1);
			}

			b.write(new VariableLengthIntegerMessage(data.length).getBytes());
			b.write(data);
		} catch (UnsupportedEncodingException e) {
			LOG.log(Level.SEVERE, "UTF-8 not supported!", e);
			System.exit(1);
		} catch (IOException e) {
			LOG.log(Level.SEVERE, "Could not write bytes!", e);
			System.exit(1);
		}

		return b.toByteArray();
	}

	public int length() {
		return new VariableLengthIntegerMessage(encoding.getConstant())
				.length()
				+ new VariableLengthIntegerMessage(data.length).length()
				+ data.length;
	}
}