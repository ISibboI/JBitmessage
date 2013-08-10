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
public class NetworkAddressMessage extends Message {
	private static final Logger LOG = Logger
			.getLogger(NetworkAddressMessage.class.getName());

	/** Timestamp describing when the node with this address was last seen. */
	private int time;

	/** The stream number of the node described by this network address. */
	private int stream;

	/** Bitfield of features that are enabled by this node. */
	private NodeServicesMessage services;

	/** IPv6 address or IPv6 mapped IPv4 address. */
	private InetAddress ip;

	/** The port of the node. */
	private int port;

	/**
	 * Creates a new network address message describing a node.
	 * 
	 * @param time The time the node was last seen.
	 * @param stream The stream the node belongs to.
	 * @param services The services the node has enabled.
	 * @param ip The ip of the node.
	 * @param port The port of the node.
	 */
	public NetworkAddressMessage(int time, int stream,
			NodeServicesMessage services, InetAddress ip, int port) {
		Objects.requireNonNull(ip, "ip must not be null!");

		if (stream == 0) {
			throw new IllegalArgumentException("stream must not be 0.");
		}

		if (port < 1 || port > 65535) {
			throw new IllegalArgumentException(
					"port must not be in range 1 - 65535");
		}

		if (!services.isSet(NodeServicesMessage.NODE_NETWORK)) {
			throw new IllegalArgumentException(
					"A node must have the NODE_NETWORK service enabled!");
		}

		this.time = time;
		this.stream = stream;
		this.services = services;
		this.ip = ip;
		this.port = port;
	}

	/**
	 * {@link Message#Message(InputBuffer)}
	 */
	public NetworkAddressMessage(InputBuffer b) throws IOException,
			ParsingException {
		super(b);
	}

	@Override
	protected void read(InputBuffer b) throws IOException, ParsingException {
		time = Util.getInt(b.get(0, 4));
		stream = Util.getInt(b.get(4, 4));
		b = b.getSubBuffer(8);

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
			throw new ParsingException("Not an IP: " + Arrays.toString(ipBytes));
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
			b.write(Util.getBytes(time));
			b.write(Util.getBytes(stream));
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

	public int getTime() {
		return time;
	}

	public int getStream() {
		return stream;
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
		return 34;
	}

	/**
	 * Returns the hash for this object, calculated only from the ip and port.
	 */
	@Override
	public int hashCode() {
		if (ip.getAddress().length == 4) {
			return Util.getInt(ip.getAddress()) + port;
		} else {
			return Util.getInt(Arrays.copyOfRange(ip.getAddress(), 12, 16))
					+ port;
		}
	}

	/**
	 * Returns true if the given object is a NetworkAddressMessage and
	 * represents the same ip and port as this message.
	 */
	@Override
	public boolean equals(Object o) {
		if (o instanceof NetworkAddressMessage) {
			NetworkAddressMessage m = (NetworkAddressMessage) o;

			return m.ip.equals(ip) && port == m.port;
		} else {
			return false;
		}
	}
}