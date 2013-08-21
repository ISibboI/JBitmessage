package sibbo.bitmessage.network.protocol;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

import sibbo.bitmessage.Options;

/**
 * A message to inform a node about my known nodes.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 * 
 */
public class AddrMessage extends P2PMessage {
	private static final Logger LOG = Logger.getLogger(AddrMessage.class.getName());

	/** The command string for this message type. */
	public static final String COMMAND = "addr";

	/** The list of addresses. */
	private List<NetworkAddressMessage> addresses;

	/**
	 * Creates a new add message.
	 * 
	 * @param addresses
	 *            The address list.
	 */
	public AddrMessage(Collection<? extends NetworkAddressMessage> addresses, MessageFactory factory) {
		super(factory);

		Objects.requireNonNull(addresses, "addresses must not be null.");

		if (addresses.size() > Options.getInstance().getInt("protocol.maxAddrLength")) {
			throw new IllegalArgumentException("Too much addresses: " + addresses.size());
		}

		this.addresses = new ArrayList<>(addresses);
	}

	/**
	 * @link {@link Message#Message(InputBuffer, MessageFactory)}
	 */
	public AddrMessage(InputBuffer b, MessageFactory factory) throws IOException, ParsingException {
		super(b, factory);
	}

	@Override
	protected void read(InputBuffer b) throws IOException, ParsingException {
		VariableLengthIntegerMessage vLength = getMessageFactory().createVariableLengthIntegerMessage(b);
		b = b.getSubBuffer(vLength.length());
		long length = vLength.getLong();

		if (length > Options.getInstance().getInt("protocol.maxAddrLength") || length < 0) {
			throw new ParsingException("Addr message too long: " + length + " addresses");
		}

		addresses = new ArrayList<NetworkAddressMessage>((int) length);

		for (int i = 0; i < length; i++) {
			NetworkAddressMessage nam = getMessageFactory().createNetworkAddressMessage(b);
			addresses.add(nam);
			b = b.getSubBuffer(nam.length());
		}
	}

	@Override
	public byte[] getBytes() {
		ByteArrayOutputStream b = new ByteArrayOutputStream();

		try {
			b.write(getMessageFactory().createVariableLengthIntegerMessage(addresses.size()).getBytes());

			for (NetworkAddressMessage addr : addresses) {
				b.write(addr.getBytes());
			}
		} catch (IOException e) {
			LOG.log(Level.SEVERE, "Could not write bytes!", e);
			System.exit(1);
		}

		return b.toByteArray();
	}

	public List<NetworkAddressMessage> getAddresses() {
		return new ArrayList<>(addresses);
	}

	@Override
	public String getCommand() {
		return COMMAND;
	}
}
