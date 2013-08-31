package sibbo.bitmessage.network.protocol;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.jce.interfaces.ECPublicKey;

import sibbo.bitmessage.crypt.CryptManager;
import sibbo.bitmessage.crypt.Digest;

/**
 * A broadcast message, basically an unencrypted message that can be read by
 * everyone in the stream.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 */
public class UnencryptedBroadcastMessage extends POWMessage {
	private static final Logger LOG = Logger.getLogger(UnencryptedBroadcastMessage.class.getName());

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
	private ECPublicKey publicSigningKey;

	/** The public encryption key of the sender. */
	private ECPublicKey publicEncryptionKey;

	/** The ripe hash of the senders address. */
	private byte[] ripe;

	/** The message. */
	private MailMessage message;

	/** The ECDSA signature of everything that is parsed by this class. */
	private byte[] signature;

	/**
	 * {@link Message#Message(InputBuffer, MessageFactory)}
	 */
	public UnencryptedBroadcastMessage(InputBuffer b, MessageFactory factory) throws IOException, ParsingException {
		super(b, factory);
	}

	public UnencryptedBroadcastMessage(long addressVersion, long stream, BehaviorMessage behavior,
			ECPublicKey publicSigningKey, ECPublicKey publicEncryptionKey, MailMessage message, MessageFactory factory) {
		super(factory);

		Objects.requireNonNull(behavior, "behavior must not be null.");
		Objects.requireNonNull(publicSigningKey, "publicSigningKey must not be null.");
		Objects.requireNonNull(publicEncryptionKey, "publicEncryptionKey must not be null.");
		Objects.requireNonNull(message, "message must not be null.");

		this.addressVersion = addressVersion;
		this.stream = stream;
		this.behavior = behavior;
		this.publicSigningKey = publicSigningKey;
		this.publicEncryptionKey = publicEncryptionKey;
		this.message = message;
	}

	public long getAddressVersion() {
		return addressVersion;
	}

	public BehaviorMessage getBehavior() {
		return behavior;
	}

	@Override
	public String getCommand() {
		return COMMAND;
	}

	public MailMessage getMessage() {
		return message;
	}

	@Override
	protected byte[] getPayloadBytes() {
		ByteArrayOutputStream b = new ByteArrayOutputStream();

		try {
			b.write(getMessageFactory().createVariableLengthIntegerMessage(BROADCAST_VERSION).getBytes());
			b.write(getMessageFactory().createVariableLengthIntegerMessage(addressVersion).getBytes());
			b.write(getMessageFactory().createVariableLengthIntegerMessage(stream).getBytes());
			b.write(behavior.getBytes());
			b.write(Util.getBytes(publicSigningKey));
			b.write(Util.getBytes(publicEncryptionKey));
			b.write(ripe);
			b.write(message.getBytes());
			b.write(getMessageFactory().createVariableLengthIntegerMessage(signature.length).getBytes());
			b.write(signature);
		} catch (IOException e) {
			LOG.log(Level.SEVERE, "Could not write bytes!", e);
			System.exit(1);
		}

		return b.toByteArray();
	}

	public ECPublicKey getPublicEncryptionKey() {
		return publicEncryptionKey;
	}

	public ECPublicKey getPublicSigningKey() {
		return publicSigningKey;
	}

	public byte[] getRipe() {
		return ripe;
	}

	public byte[] getSignature() {
		return signature;
	}

	public long getStream() {
		return stream;
	}

	@Override
	protected void readPayload(InputBuffer b) throws IOException, ParsingException {
		InputBuffer signed = b.getSubBuffer(0);

		VariableLengthIntegerMessage v = getMessageFactory().parseVariableLengthIntegerMessage(b);
		b = b.getSubBuffer(v.length());

		if (BROADCAST_VERSION != v.getLong()) {
			throw new ParsingException("Unknown broadcast message version: " + v.getLong());
		}

		v = getMessageFactory().parseVariableLengthIntegerMessage(b);
		b = b.getSubBuffer(v.length());
		addressVersion = v.getLong();

		v = getMessageFactory().parseVariableLengthIntegerMessage(b);
		b = b.getSubBuffer(v.length());
		stream = v.getLong();

		behavior = getMessageFactory().parseBehaviorMessage(b);
		b = b.getSubBuffer(behavior.length());

		publicSigningKey = Util.getPublicKey(b.get(0, 64));
		publicEncryptionKey = Util.getPublicKey(b.get(64, 64));
		ripe = b.get(128, 20);
		b = b.getSubBuffer(148);

		if (!Arrays.equals(Digest.keyDigest(publicSigningKey, publicEncryptionKey), ripe)) {
			throw new ParsingException("The hash of the public keys is incorrect.");
		}

		message = getMessageFactory().parseMailMessage(b);
		b = b.getSubBuffer(message.length());

		v = getMessageFactory().parseVariableLengthIntegerMessage(b);
		b = b.getSubBuffer(v.length());
		long length = v.getLong();

		if (length < 0 || length > b.length()) {
			throw new ParsingException("ECDSA signature too long: " + length);
		}

		signature = b.get(0, (int) length);

		if (!CryptManager.getInstance().verifySignature(signed.get(0, b.getOffset() - signed.getOffset()), signature,
				publicSigningKey)) {
			throw new ParsingException("Wrong signature.");
		}
	}
}