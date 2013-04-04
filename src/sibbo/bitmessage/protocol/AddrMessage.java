package sibbo.bitmessage.protocol;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A message to inform a node about my known nodes.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 * 
 */
public class AddrMessage extends P2PMessage {
	private static final Logger LOG = Logger.getLogger(AddrMessage.class
			.getName());

	/** The command string for this message type. */
	public static final String COMMAND = "addr";

	/** The list of addresses. */
	private NetworkAddressMessage[] addresses;

	/**
	 * Creates a new add message.
	 * 
	 * @param addresses The address list.
	 */
	public AddrMessage(NetworkAddressMessage[] addresses) {
		this.addresses = addresses;
	}

	/**
	 * @link {@link Message#Message(InputBuffer)}
	 */
	public AddrMessage(InputBuffer b) throws IOException, ParsingException {
		super(b);
	}

	@Override
	protected void read(InputBuffer b) throws IOException, ParsingException {
		VariableLengthIntegerMessage vLength = new VariableLengthIntegerMessage(
				b);
		b = b.getSubBuffer(vLength.length());
		long length = vLength.getLong();

		if (length > 1000 || length < 0) {
			throw new ParsingException("Addr message too long: " + length
					+ " addresses");
		}

		addresses = new NetworkAddressMessage[(int) length];

		for (int i = 0; i < addresses.length; i++) {
			addresses[i] = new NetworkAddressMessage(b);
			b = b.getSubBuffer(addresses[i].length());
		}
	}

	@Override
	public byte[] getBytes() {
		ByteArrayOutputStream b = new ByteArrayOutputStream();

		try {
			b.write(new VariableLengthIntegerMessage(addresses.length)
					.getBytes());

			for (NetworkAddressMessage addr : addresses) {
				b.write(addr.getBytes());
			}
		} catch (IOException e) {
			LOG.log(Level.SEVERE, "Could not write bytes!", e);
			System.exit(1);
		}

		return b.toByteArray();
	}

	public NetworkAddressMessage[] getAddresses() {
		return addresses;
	}

	@Override
	public String getCommand() {
		return COMMAND;
	}
}
