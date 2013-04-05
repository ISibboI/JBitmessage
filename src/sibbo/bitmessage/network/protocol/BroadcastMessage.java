package sibbo.bitmessage.network.protocol;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A broadcast message, basically an unencrypted message that can be read by
 * everyone in the stream.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 */
public class BroadcastMessage extends POWMessage {
	private static final Logger LOG = Logger.getLogger(BroadcastMessage.class
			.getName());

	public static final String COMMAND = "broadcast";

	/** The version that this class implements. */
	private static final long BROADCAST_VERSION = 1;

	/** The version of the senders address. */
	private long addressVersion;

	/** The stream of the sender. */
	private long stream;

	/** The behavior of the sender. */
	private BehaviorMessage behavior;

	/** The public signing key of the sender. */
	private byte[] publicSigningKey;

	/** The public encryption key of the sender. */
	private byte[] publicEncryptionKey;

	/** The ripe hash of the senders address. */
	private byte[] ripe;

	/** The message. */
	private MailMessage message;

	/** The ECDSA signature of everything that is parsed by this class. */
	private byte[] signature;

	public BroadcastMessage(long addressVersion, long stream,
			BehaviorMessage behavior, byte[] publicSigningKey,
			byte[] publicEncryptionKey, MailMessage message) {
		Objects.requireNonNull(behavior, "behavior must not be null.");
		Objects.requireNonNull(publicSigningKey,
				"publicSigningKey must not be null.");
		Objects.requireNonNull(publicEncryptionKey,
				"publicEncryptionKey must not be null.");
		Objects.requireNonNull(message, "message must not be null.");

		if (publicSigningKey.length != 64) {
			throw new IllegalArgumentException(
					"publicSigningKey must not be null.");
		}

		if (publicEncryptionKey.length != 64) {
			throw new IllegalArgumentException(
					"publicEncryptionKey must not be null.");
		}

		this.addressVersion = addressVersion;
		this.stream = stream;
		this.behavior = behavior;
		this.publicSigningKey = publicSigningKey;
		this.publicEncryptionKey = publicEncryptionKey;
		this.message = message;
	}

	/**
	 * {@link Message#Message(InputBuffer)}
	 */
	public BroadcastMessage(InputBuffer b) throws IOException, ParsingException {
		super(b);
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

	public byte[] getRipe() {
		return ripe;
	}

	public MailMessage getMessage() {
		return message;
	}

	public byte[] getSignature() {
		return signature;
	}

	@Override
	protected void readPayload(InputBuffer b) throws IOException,
			ParsingException {
		VariableLengthIntegerMessage v = new VariableLengthIntegerMessage(b);
		b = b.getSubBuffer(v.length());

		if (BROADCAST_VERSION != v.getLong()) {
			throw new ParsingException("Unknown broadcast message version: "
					+ v.getLong());
		}

		v = new VariableLengthIntegerMessage(b);
		b = b.getSubBuffer(v.length());
		addressVersion = v.getLong();

		v = new VariableLengthIntegerMessage(b);
		b = b.getSubBuffer(v.length());
		stream = v.getLong();

		behavior = new BehaviorMessage(b);
		b = b.getSubBuffer(behavior.length());

		publicSigningKey = b.get(0, 64);
		publicEncryptionKey = b.get(64, 64);
		ripe = b.get(128, 20);
		b = b.getSubBuffer(148);

		message = new MailMessage(b);
		b = b.getSubBuffer(message.length());

		v = new VariableLengthIntegerMessage(b);
		b = b.getSubBuffer(v.length());
		long length = v.getLong();

		if (length < 0 || length > b.length()) {
			throw new ParsingException("ECDSA signature too long: " + length);
		}

		signature = b.get(0, (int) length);
	}

	@Override
	protected byte[] getPayloadBytes() {
		ByteArrayOutputStream b = new ByteArrayOutputStream();

		try {
			b.write(new VariableLengthIntegerMessage(BROADCAST_VERSION)
					.getBytes());
			b.write(new VariableLengthIntegerMessage(addressVersion).getBytes());
			b.write(new VariableLengthIntegerMessage(stream).getBytes());
			b.write(behavior.getBytes());
			b.write(publicSigningKey);
			b.write(publicEncryptionKey);
			b.write(ripe);
			b.write(message.getBytes());
			b.write(new VariableLengthIntegerMessage(signature.length)
					.getBytes());
			b.write(signature);
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