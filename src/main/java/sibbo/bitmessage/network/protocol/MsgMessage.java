package sibbo.bitmessage.network.protocol;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * An encrypted p2p message.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 */
public class MsgMessage extends POWMessage {
	private static final Logger LOG = Logger.getLogger(MsgMessage.class.getName());

	/** The command string for this message type. */
	public static final String COMMAND = "msg";

	/** The stream of the destination. */
	private long stream;

	/** The encrypted message. */
	private EncryptedMessage encrypted;

	/**
	 * Creates a new msg message.
	 * 
	 * @param stream
	 * @param encrypted
	 */
	public MsgMessage(long stream, EncryptedMessage encrypted) {
		Objects.requireNonNull(encrypted);

		if (stream == 0) {
			throw new IllegalArgumentException("stream must not be 0.");
		}

		this.stream = stream;
		this.encrypted = encrypted;
	}

	/**
	 * {@link Message#Message(InputBuffer)}
	 */
	public MsgMessage(InputBuffer b) throws IOException, ParsingException {
		super(b);
	}

	public long getStream() {
		return stream;
	}

	public EncryptedMessage getEncrypted() {
		return encrypted;
	}

	@Override
	protected void readPayload(InputBuffer b) throws IOException, ParsingException {
		VariableLengthIntegerMessage v = new VariableLengthIntegerMessage(b);
		b = b.getSubBuffer(v.length());
		stream = v.getLong();

		encrypted = new EncryptedMessage(b);
	}

	@Override
	protected byte[] getPayloadBytes() {
		ByteArrayOutputStream b = new ByteArrayOutputStream();

		try {
			b.write(new VariableLengthIntegerMessage(stream).getBytes());
			b.write(encrypted.getBytes());
		} catch (IOException e) {
			LOG.log(Level.SEVERE, "Could not write bytes!", e);
			System.exit(1);
		}

		return b.toByteArray();
	}

	@Override
	public String getCommand() {
		return COMMAND;
	}
}