package sibbo.bitmessage.protocol;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.logging.Level;
import java.util.logging.Logger;

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
	private static final long VERSION = 1;

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
	 * {@link Message#Message(InputStream, int)}
	 */
	public UnencryptedMessageDataMessage(InputStream in, int maxLength)
			throws IOException, ParsingException {
		super(in, maxLength);
	}

	@Override
	protected void read(InputStream in, int maxLength) throws IOException,
			ParsingException {
		long messageVersion = new VariableLengthIntegerMessage(in, maxLength)
				.getLong();

		if (messageVersion != VERSION) {
			throw new ParsingException(
					"Cannot understand messages of version: " + messageVersion);
		}

		addressVersion = new VariableLengthIntegerMessage(in, maxLength)
				.getLong();

		if (!BitMessageAddress.isSupported(addressVersion)) {
			throw new ParsingException("Unknown address version: "
					+ addressVersion);
		}

		stream = new VariableLengthIntegerMessage(in, maxLength).getLong();
		behavior = new BehaviorMessage(in, maxLength);

		publicSigningKey = new byte[64];
		readComplete(in, publicSigningKey);

		publicEncryptionKey = new byte[64];
		readComplete(in, publicEncryptionKey);

		destinationRipe = new byte[20];
		readComplete(in, destinationRipe);

		message = new MailMessage(in, maxLength);

		long length = new VariableLengthIntegerMessage(in, maxLength).getLong();

		if (length < 0 || length > maxLength) {
			throw new ParsingException("The acknowlegment data is too long: "
					+ length);
		}

		byte[] acknowledgment = new byte[(int) length];
		readComplete(in, acknowledgment);
		ByteArrayInputStream ackIn = new ByteArrayInputStream(acknowledgment);
		this.acknowledgment = new BaseMessage(ackIn, acknowledgment.length);

		length = new VariableLengthIntegerMessage(in, maxLength).getLong();

		if (length < 0 || length > maxLength) {
			throw new ParsingException("The signature data is too long: "
					+ length);
		}

		signature = new byte[(int) length];
		readComplete(in, signature);

		CryptManager.checkSignature(getBytesWithoutSignature(), signature);
	}

	private byte[] getBytesWithoutSignature() {
		// TODO Auto-generated method stub
		return null;
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
}