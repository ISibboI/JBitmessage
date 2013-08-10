package sibbo.bitmessage.network.protocol;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A message that contains a network address.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 */
public class SimpleNetworkAddressMessage extends Message {
	private static final Logger LOG = Logger
			.getLogger(NetworkAddressMessage.class.getName());

	/** Bitfield of features that are enabled by this node. */
	private NodeServicesMessage services;

	/** IPv6 address or IPv6 mapped IPv4 address. */
	private InetAddress ip;

	/** The port of the node. */
	private int port;

	/**
	 * Creates a new network address message describing a node.
	 * 
	 * @param services The services the node has enabled.
	 * @param ip The ip of the node.
	 * @param port The port of the node.
	 */
	public SimpleNetworkAddressMessage(NodeServicesMessage services,
			InetAddress ip, int port) {
		Objects.requireNonNull(ip, "ip must not be null!");

		if (port < 1 || port > 65535) {
			throw new IllegalArgumentException(
					"port must not be in range 1 - 65535");
		}

		if (!services.isSet(NodeServicesMessage.NODE_NETWORK)) {
			throw new IllegalArgumentException(
					"A node must have the NODE_NETWORK service enabled!");
		}

		this.services = services;
		this.ip = ip;
		this.port = port;
	}

	/**
	 * {@link Message#Message(InputBuffer)}
	 */
	public SimpleNetworkAddressMessage(InputBuffer b) throws IOException,
			ParsingException {
		super(b);
	}

	@Override
	protected void read(InputBuffer b) throws IOException, ParsingException {
		services = new NodeServicesMessage(b);
		b = b.getSubBuffer(services.length());

		byte[] ipBytes = b.get(0, 16);

		try {
			if (isIpv4(ipBytes)) {
				ip = InetAddress.getByAddress(Arrays.copyOfRange(ipBytes, 12,
						16));
			} else {
				ip = InetAddress.getByAddress(ipBytes);
			}
		} catch (UnknownHostException e) {
			if (isIpv4(ipBytes)) {
				throw new ParsingException("Not an IP: "
						+ Arrays.toString(Arrays.copyOfRange(ipBytes, 12, 16)));
			} else {
				throw new ParsingException("Not an IP: "
						+ Arrays.toString(ipBytes));
			}
		}

		byte[] portBytes = b.get(16, 2);
		port = Util.getInt(new byte[] { 0, 0, portBytes[0], portBytes[1] });

		if (ip.isAnyLocalAddress() || ip.isMulticastAddress()) {
			throw new ParsingException("IP is local or multicast!");
		}

		boolean isNull = true;

		for (byte a : ip.getAddress()) {
			if (a != 0) {
				isNull = false;
			}
		}

		if (isNull) {
			throw new ParsingException("IP is 0");
		}
	}

	@Override
	public byte[] getBytes() {
		ByteArrayOutputStream b = new ByteArrayOutputStream(34);

		try {
			b.write(services.getBytes());

			byte[] ip = this.ip.getAddress();
			if (ip.length == 4) {
				byte[] tmpip = new byte[16];

				tmpip[10] = tmpip[11] = -1;
				tmpip[12] = ip[0];
				tmpip[13] = ip[1];
				tmpip[14] = ip[2];
				tmpip[15] = ip[3];

				ip = tmpip;
			}

			b.write(ip);

			byte[] port = Util.getBytes(this.port);
			b.write(new byte[] { port[2], port[3] });
		} catch (IOException e) {
			LOG.log(Level.SEVERE, "Could not write bytes!", e);
			System.exit(1);
		}

		return b.toByteArray();
	}

	public NodeServicesMessage getServices() {
		return services;
	}

	public InetAddress getIp() {
		return ip;
	}

	/**
	 * Returns true if the given 16 byte ip-address is an IPv4 address, false if
	 * it is an IPv6 address.
	 * 
	 * @param ip An IPv6 address or v6 mapped v4 address.
	 * @return True if the given 16 byte ip-address is an IPv4 address, false if
	 *         it is an IPv6 address.
	 */
	public boolean isIpv4(byte[] ip) {
		if (ip.length != 16) {
			throw new IllegalArgumentException("ip must have a length of 16.");
		}

		byte[] prefix = new byte[12];
		prefix[10] = prefix[11] = -1;

		return Arrays.equals(Arrays.copyOf(ip, 12), prefix);
	}

	public int getPort() {
		return port;
	}

	public int length() {
		return 26;
	}
}