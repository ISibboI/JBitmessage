package sibbo.bitmessage.network.protocol;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Represents a mail.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 */
public class MailMessage extends Message {
	private static final Logger LOG = Logger.getLogger(MailMessage.class.getName());

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

	public MailMessage(MessageEncoding encoding, byte[] data, String subject, String content, MessageFactory factory) {
		super(factory);

		this.encoding = encoding;

		this.data = data;
		this.subject = subject;
		this.content = content;
	}

	/**
	 * {@link Message#Message(InputBuffer, MessageFactory)}
	 */
	public MailMessage(InputBuffer b, MessageFactory factory) throws IOException, ParsingException {
		super(b, factory);
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
		VariableLengthIntegerMessage i = getMessageFactory().parseVariableLengthIntegerMessage(b);
		b = b.getSubBuffer(i.length());
		encoding = MessageEncoding.getEncoding(i.getLong());

		i = getMessageFactory().parseVariableLengthIntegerMessage(b);
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
			b.write(getMessageFactory().createVariableLengthIntegerMessage(encoding.getConstant()).getBytes());

			switch (encoding) {
			case IGNORE:
				break;

			case TRIVIAL:
				data = content.getBytes("UTF-8");
				break;

			case SIMPLE:
				data = ("Subject:" + subject + "\nBody:" + content).getBytes();
				break;

			default:
				LOG.log(Level.SEVERE, "Unknown encoding: " + encoding);
				System.exit(1);
			}

			b.write(getMessageFactory().createVariableLengthIntegerMessage(data.length).getBytes());
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
		return getMessageFactory().createVariableLengthIntegerMessage(encoding.getConstant()).length()
				+ getMessageFactory().createVariableLengthIntegerMessage(data.length).length() + data.length;
	}
}