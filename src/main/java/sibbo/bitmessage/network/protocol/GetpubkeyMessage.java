package sibbo.bitmessage.network.protocol;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A message to request a public key fitting to its ripe.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 */
public class GetpubkeyMessage extends POWMessage {
	private static final Logger LOG = Logger.getLogger(GetpubkeyMessage.class.getName());

	/** The command string for this message type. */
	public static final String COMMAND = "getpubkey";

	/** The version of the address. */
	private long addressVersion;

	/** The stream of the address. */
	private long streamNumber;

	/** The ripe hash of the address. */
	private byte[] ripe;

	/**
	 * Creates a new getpubkey message.
	 * 
	 * @param time
	 *            The time the message was sent.
	 * @param addressVersion
	 *            The version number of the requested address.
	 * @param streamNumber
	 *            The stream number of the requested address.
	 * @param ripe
	 *            The ripe hash of the requested address.
	 */
	public GetpubkeyMessage(long addressVersion, long streamNumber, byte[] ripe, MessageFactory factory) {
		super(factory);

		Objects.requireNonNull(ripe, "ripe must not be null.");

		if (ripe.length != 20) {
			throw new IllegalArgumentException("ripe must have a length of 20.");
		}

		this.addressVersion = addressVersion;
		this.streamNumber = streamNumber;
		this.ripe = ripe;
	}

	public long getAddressVersion() {
		return addressVersion;
	}

	public long getStreamNumber() {
		return streamNumber;
	}

	public byte[] getRipe() {
		return ripe;
	}

	/**
	 * {@link Message#Message(InputBuffer, MessageFactory)}
	 */
	public GetpubkeyMessage(InputBuffer b, MessageFactory factory) throws IOException, ParsingException {
		super(b, factory);
	}

	@Override
	protected void readPayload(InputBuffer b) throws IOException, ParsingException {
		VariableLengthIntegerMessage v = getMessageFactory().parseVariableLengthIntegerMessage(b);
		b = b.getSubBuffer(v.length());
		addressVersion = v.getLong();

		v = getMessageFactory().parseVariableLengthIntegerMessage(b);
		b = b.getSubBuffer(v.length());
		streamNumber = v.getLong();

		ripe = b.get(0, 20);
	}

	@Override
	protected byte[] getPayloadBytes() {
		ByteArrayOutputStream b = new ByteArrayOutputStream();

		try {
			b.write(getMessageFactory().createVariableLengthIntegerMessage(addressVersion).getBytes());
			b.write(getMessageFactory().createVariableLengthIntegerMessage(streamNumber).getBytes());
			b.write(ripe);
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