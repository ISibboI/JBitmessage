package sibbo.bitmessage.network.protocol;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import sibbo.bitmessage.crypt.BMAddress;
import sibbo.bitmessage.crypt.CryptManager;

/**
 * Data to be sent within a msg message.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 * 
 */
public class UnencryptedMessageDataMessage extends Message {
	private static final Logger LOG = Logger
			.getLogger(UnencryptedMessageDataMessage.class.getName());

	/** This class implements version 1 messages. */
	public static final long MESSAGE_VERSION = 1;

	/** The version of the bitmessage address. */
	private long addressVersion;

	/** The stream number of the sender. */
	private long stream;

	/** The behavior that can be expected of the sender. */
	private BehaviorMessage behavior;

	/** The ECC public key of the sender used for signing. */
	private byte[] publicSigningKey;

	/** The ECC public key of the sender used for encryption. */
	private byte[] publicEncryptionKey;

	/** The ripe hash of the public key of the receiver of the message. */
	private byte[] destinationRipe;

	/** The actual message. */
	private MailMessage message;

	/** The acknowledgment message. */
	private BaseMessage acknowledgment;

	/** The ECDSA signature */
	private byte[] signature;

	/**
	 * Creates a new unencrypted message data message with the given parameters.
	 * 
	 * @param addressVersion The version of the sender address.
	 * @param stream The stream of the sender.
	 * @param behavior The behavior of the sender.
	 * @param publicSigningKey The public key of the sender used for signing.
	 * @param publicEncryptionKey The public key of the sender used for
	 *            encryption.
	 * @param destinationRipe The ripe hash of the senders bitmessage address.
	 * @param message The actual message.
	 * @param acknowledgment The acknowledgment message.
	 */
	public UnencryptedMessageDataMessage(long addressVersion, long stream,
			BehaviorMessage behavior, byte[] publicSigningKey,
			byte[] publicEncryptionKey, byte[] destinationRipe,
			MailMessage message, BaseMessage acknowledgment) {
		this.addressVersion = addressVersion;
		this.stream = stream;
		this.behavior = behavior;
		this.publicSigningKey = publicSigningKey;
		this.publicEncryptionKey = publicEncryptionKey;
		this.destinationRipe = destinationRipe;
		this.message = message;
		this.acknowledgment = acknowledgment;
	}

	/**
	 * {@link Message#Message(InputBuffer)}
	 */
	public UnencryptedMessageDataMessage(InputBuffer b) throws IOException,
			ParsingException {
		super(b);
	}

	@Override
	protected void read(InputBuffer b) throws IOException, ParsingException {
		InputBuffer signed = b.getSubBuffer(0);

		VariableLengthIntegerMessage messageVersion = new VariableLengthIntegerMessage(
				b);
		b = b.getSubBuffer(messageVersion.length());

		if (messageVersion.getLong() != MESSAGE_VERSION) {
			throw new ParsingException(
					"Cannot understand messages of version: " + messageVersion);
		}

		VariableLengthIntegerMessage vAddressVersion = new VariableLengthIntegerMessage(
				b);
		b = b.getSubBuffer(vAddressVersion.length());
		addressVersion = vAddressVersion.getLong();

		if (!BMAddress.isSupported(addressVersion)) {
			throw new ParsingException("Unknown address version: "
					+ addressVersion);
		}

		VariableLengthIntegerMessage vStream = new VariableLengthIntegerMessage(
				b);
		b = b.getSubBuffer(vStream.length());
		stream = vStream.getLong();

		behavior = new BehaviorMessage(b);
		b = b.getSubBuffer(behavior.length());

		publicSigningKey = b.get(0, 64);

		publicEncryptionKey = b.get(64, 64);

		destinationRipe = b.get(84, 64);
		b = b.getSubBuffer(148);

		message = new MailMessage(b);
		b = b.getSubBuffer(message.length());

		VariableLengthIntegerMessage vLength = new VariableLengthIntegerMessage(
				b);
		b = b.getSubBuffer(vLength.length());
		long length = vLength.getLong();

		if (length < 0 || length > b.length()) {
			throw new ParsingException("The acknowlegment data is too long: "
					+ length);
		}

		this.acknowledgment = new BaseMessage(new InputBufferInputStream(
				b.getSubBuffer(0, (int) length)), (int) length);
		b = b.getSubBuffer((int) length);

		vLength = new VariableLengthIntegerMessage(b);
		b = b.getSubBuffer(vLength.length());
		length = vLength.getLong();

		if (length < 0 || length > b.length()) {
			throw new ParsingException("The signature data is too long: "
					+ length);
		}

		signature = b.get(0, (int) length);

		if (!CryptManager.getInstance().checkSignature(
				signed.get(0, b.getOffset() - signed.getOffset()), signature,
				publicSigningKey)) {
			throw new ParsingException("Wrong signature.");
		}
	}

	private byte[] getBytesWithoutSignature() {
		ByteArrayOutputStream b = new ByteArrayOutputStream();

		try {
			b.write(new VariableLengthIntegerMessage(MESSAGE_VERSION)
					.getBytes());
			b.write(new VariableLengthIntegerMessage(addressVersion).getBytes());
			b.write(new VariableLengthIntegerMessage(stream).getBytes());
			b.write(behavior.getBytes());
			b.write(publicSigningKey);
			b.write(publicEncryptionKey);
			b.write(destinationRipe);
			b.write(message.getBytes());

			byte[] ack = acknowledgment.getBytes();
			b.write(new VariableLengthIntegerMessage(ack.length).getBytes());
			b.write(ack);
		} catch (IOException e) {
			LOG.log(Level.SEVERE, "Could not write bytes!", e);
			System.exit(1);
		}

		return b.toByteArray();
	}

	@Override
	public byte[] getBytes() {
		ByteArrayOutputStream b = new ByteArrayOutputStream();

		try {
			b.write(getBytesWithoutSignature());
			b.write(new VariableLengthIntegerMessage(signature.length)
					.getBytes());
			b.write(signature);
		} catch (IOException e) {
			LOG.log(Level.SEVERE, "Could not write bytes!", e);
			System.exit(1);
		}

		return b.toByteArray();
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

	public byte[] getDestinationRipe() {
		return destinationRipe;
	}

	public MailMessage getMessage() {
		return message;
	}

	public BaseMessage getAcknowledgment() {
		return acknowledgment;
	}
}