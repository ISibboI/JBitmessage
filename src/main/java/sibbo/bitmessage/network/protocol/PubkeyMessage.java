package sibbo.bitmessage.network.protocol;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A message containing a public key.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 */
public class PubkeyMessage extends POWMessage {
	private static final Logger LOG = Logger.getLogger(PubkeyMessage.class.getName());

	/** The command string for this message type. */
	public static final String COMMAND = "pubkey";

	/** The version of the bitmessage address. */
	private long addressVersion;

	/** The stream of the address. */
	private long stream;

	/** The behavior that can be expected from the node receiving the message. */
	private BehaviorMessage behavior;

	/** The public signing key. */
	private byte[] publicSigningKey;

	/** The public encryption key. */
	private byte[] publicEncryptionKey;

	/**
	 * Creates a new pubkey message.
	 * 
	 * @param addressVersion
	 *            The version of the public key.
	 * @param stream
	 *            The stream of the public key.
	 * @param behavior
	 *            The behavior of the node that uses this public key.
	 * @param publicSigningKey
	 *            The public signing key.
	 * @param publicEncryptionKey
	 *            The public encryption key.
	 */
	public PubkeyMessage(long addressVersion, long stream, BehaviorMessage behavior, byte[] publicSigningKey,
			byte[] publicEncryptionKey, MessageFactory factory) {
		super(factory);

		Objects.requireNonNull(behavior, "behavior must not be null.");
		Objects.requireNonNull(publicSigningKey, "publicSigningKey must not be null.");
		Objects.requireNonNull(publicEncryptionKey, "publicEncryptionKey must not be null.");

		if (stream == 0) {
			throw new IllegalArgumentException("stream must not be 0.");
		}

		this.addressVersion = addressVersion;
		this.stream = stream;
		this.behavior = behavior;
		this.publicSigningKey = publicSigningKey;
		this.publicEncryptionKey = publicEncryptionKey;
	}

	/**
	 * {@link Message#Message(InputBuffer, MessageFactory)}
	 */
	public PubkeyMessage(InputBuffer b, MessageFactory factory) throws IOException, ParsingException {
		super(b, factory);
	}

	public long getAddressVersion() {
		return addressVersion;
	}

	public long getStream() {
		return stream;
	}

	public BehaviorMessage getBehavior() {
		return behavior;
	}

	public byte[] getPublicSigningKey() {
		return publicSigningKey;
	}

	public byte[] getPublicEncryptionKey() {
		return publicEncryptionKey;
	}

	@Override
	protected void readPayload(InputBuffer b) throws IOException, ParsingException {
		VariableLengthIntegerMessage v = getMessageFactory().parseVariableLengthIntegerMessage(b);
		b = b.getSubBuffer(v.length());
		addressVersion = v.getLong();

		v = getMessageFactory().parseVariableLengthIntegerMessage(b);
		b = b.getSubBuffer(v.length());
		stream = v.getLong();

		behavior = getMessageFactory().parseBehaviorMessage(b);
		b = b.getSubBuffer(behavior.length());

		publicSigningKey = b.get(0, 64);
		publicEncryptionKey = b.get(64, 64);
	}

	@Override
	protected byte[] getPayloadBytes() {
		ByteArrayOutputStream b = new ByteArrayOutputStream();

		try {
			b.write(getMessageFactory().createVariableLengthIntegerMessage(addressVersion).getBytes());
			b.write(getMessageFactory().createVariableLengthIntegerMessage(stream).getBytes());
			b.write(behavior.getBytes());
			b.write(publicSigningKey);
			b.write(publicEncryptionKey);
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