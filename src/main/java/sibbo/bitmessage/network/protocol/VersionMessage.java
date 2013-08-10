package sibbo.bitmessage.network.protocol;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A version message, used for handshake with another node.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 */
public class VersionMessage extends P2PMessage {
	private static final Logger LOG = Logger.getLogger(VersionMessage.class
			.getName());

	/** The command string for this message type. */
	public static final String COMMAND = "version";

	/** The protocol version is 1. */
	public static final int PROTOCOL_VERSION = 1;

	/** The services enabled by this node. */
	private NodeServicesMessage services;

	/** Standard unix timestamp on seconds. */
	private long timestamp;

	/** The address of the receiver. */
	private SimpleNetworkAddressMessage receiver;

	/** The address of the sender. */
	private SimpleNetworkAddressMessage sender;

	/**
	 * Random nonce used to detect connections to self. (See protocol
	 * specification)
	 */
	private long nonce;

	/** User Agent. */
	private String userAgent;

	/** The streams the sender is interested in. */
	private long[] streams;

	/**
	 * Creates a new version message with the given parameters.
	 * 
	 * @param services The services enabled by the sender.
	 * @param timestamp Standard Unix timestamp in seconds.
	 * @param receiver The address of the receiver.
	 * @param sender The address of the sender.
	 * @param nonce Random nonce used to detect connections to self.
	 * @param userAgent The User Agent of the sender.
	 * @param streams The streams the sender is interested in.
	 */
	public VersionMessage(NodeServicesMessage services, long timestamp,
			SimpleNetworkAddressMessage receiver,
			SimpleNetworkAddressMessage sender, long nonce, String userAgent,
			long[] streams) {
		this.services = services;
		this.timestamp = timestamp;
		this.receiver = receiver;
		this.sender = sender;
		this.nonce = nonce;
		this.userAgent = userAgent;
		this.streams = streams;
	}

	public NodeServicesMessage getServices() {
		return services;
	}

	public long getTimestamp() {
		return timestamp;
	}

	public SimpleNetworkAddressMessage getReceiver() {
		return receiver;
	}

	public SimpleNetworkAddressMessage getSender() {
		return sender;
	}

	public long getNonce() {
		return nonce;
	}

	public String getUserAgent() {
		return userAgent;
	}

	public long[] getStreams() {
		return streams;
	}

	/**
	 * {@link Message#Message(InputBuffer)}
	 */
	public VersionMessage(InputBuffer b) throws IOException, ParsingException {
		super(b);
	}

	@Override
	protected void read(InputBuffer b) throws IOException, ParsingException {
		int version = Util.getInt(b.get(0, 4));
		b = b.getSubBuffer(4);

		if (version != PROTOCOL_VERSION) {
			throw new ParsingException("Unsupported protocol version: "
					+ version);
		}

		services = new NodeServicesMessage(b);
		b = b.getSubBuffer(services.length());

		timestamp = Util.getLong(b.get(0, 8));
		b = b.getSubBuffer(8);

		receiver = new SimpleNetworkAddressMessage(b);
		b = b.getSubBuffer(receiver.length());

		sender = new SimpleNetworkAddressMessage(b);
		b = b.getSubBuffer(sender.length());

		nonce = Util.getLong(b.get(0, 8));
		b = b.getSubBuffer(8);

		VariableLengthStringMessage vUserAgent = new VariableLengthStringMessage(
				b);
		b = b.getSubBuffer(vUserAgent.length());
		userAgent = vUserAgent.getMessage();

		streams = new VariableLengthIntegerListMessage(b).getContent();
	}

	@Override
	public byte[] getBytes() {
		ByteArrayOutputStream b = new ByteArrayOutputStream();

		try {
			b.write(Util.getBytes(PROTOCOL_VERSION));
			b.write(services.getBytes());
			b.write(Util.getBytes(timestamp));
			b.write(receiver.getBytes());
			b.write(sender.getBytes());
			b.write(Util.getBytes(nonce));
			b.write(new VariableLengthStringMessage(userAgent).getBytes());
			b.write(new VariableLengthIntegerListMessage(streams).getBytes());
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