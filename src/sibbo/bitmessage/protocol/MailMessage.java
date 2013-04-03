package sibbo.bitmessage.protocol;

import java.io.IOException;
import java.io.InputStream;
import java.util.logging.Logger;

import sibbo.bitmessage.Options;

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

	private byte[] data;

	private String subject;

	private String content;

	private MailMessage(MessageEncoding encoding, byte[] data, String subject,
			String content) {
		this.encoding = encoding;

		this.data = data;
		this.subject = subject;
		this.content = content;
	}

	/**
	 * {@link Message#Message(InputStream)}
	 */
	public MailMessage(InputStream in, int maxLength) throws IOException,
			ParsingException {
		super(in, maxLength);
	}

	/**
	 * Returns a new IGNORE message. The given data is probably ignored by the
	 * receiver.
	 * 
	 * @param data Probably ignored by the receiver.
	 * @return A new ignore message.
	 */
	public static MailMessage getIgnoreMessage(byte[] data) {
		return new MailMessage(MessageEncoding.IGNORE, data, null, null);
	}

	/**
	 * Returns a new TRIVIAL message.
	 * 
	 * @param content The message text.
	 * @return A new trivial message.
	 */
	public static MailMessage getTrivialMessage(String content) {
		return new MailMessage(MessageEncoding.IGNORE, null, null, content);
	}

	/**
	 * Returns a new SIMPLE message.
	 * 
	 * @param subject The message subject.
	 * @param content The message text.
	 * @return A new simple message.
	 */
	public static MailMessage getTrivialMessage(String subject, String content) {
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
	protected void read(InputStream in, int maxLength) throws IOException,
			ParsingException {
		VariableLengthIntegerMessage i = new VariableLengthIntegerMessage(in,
				maxLength);
		encoding = MessageEncoding.getEncoding(i.getLong());

		long length = new VariableLengthIntegerMessage(in, maxLength).getLong();

		if (length > Options.getInstance().getMaxMessageLength() || length < 0) {
			throw new ParsingException("Message too long: " + length);
		}
	}

	@Override
	public byte[] getBytes() {
		// TODO Auto-generated method stub
		return null;
	}
}