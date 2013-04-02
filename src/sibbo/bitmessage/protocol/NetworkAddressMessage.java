package sibbo.bitmessage.protocol;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
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
	private byte[] time; // 4

	/** The stream number of the node described by this network address. */
	private byte[] stream; // 4

	/** Bitfield of features that are enabled by this node. */
	private byte[] services; // 8

	/** IPv6 address or IPv6 mapped IPv4 address. */
	private byte[] ip; // 16

	/** The port of the node. */
	private byte[] port; // 2

	/**
	 * Creates a new network address message describing a node.
	 * 
	 * @param time The time the node was last seen.
	 * @param stream The stream the node belongs to.
	 * @param services The services the node has enabled.
	 * @param ip The ip of the node.
	 * @param port The port of the node.
	 */
	public NetworkAddressMessage(int time, int stream, long services,
			InetAddress ip, int port) {
		Objects.requireNonNull(ip, "ip must not be null!");

		if (stream == 0) {
			throw new IllegalArgumentException("stream must not be 0.");
		}

		if (port < 1 || port > 65535) {
			throw new IllegalArgumentException(
					"port must not be in range 1 - 65535");
		}

		if (!NodeServices.checkService(services, NodeServices.NODE_NETWORK)) {
			throw new IllegalArgumentException(
					"A node must have the NODE_NETWORK service enabled!");
		}

		this.time = Util.getBytes(time);
		this.stream = Util.getBytes(stream);
		this.services = Util.getBytes(services);

		this.ip = ip.getAddress();
		if (this.ip.length == 4) {
			byte[] tmpip = new byte[16];

			tmpip[10] = tmpip[11] = -1;
			tmpip[12] = this.ip[0];
			tmpip[13] = this.ip[1];
			tmpip[14] = this.ip[2];
			tmpip[15] = this.ip[3];

			this.ip = tmpip;
		}

		byte[] tmpport = Util.getBytes(port);
		this.port = new byte[] { tmpport[2], tmpport[3] };
	}

	/**
	 * {@link Message#Message(InputStream)}
	 */
	public NetworkAddressMessage(InputStream in) throws IOException,
			ParsingException {
		super(in);
	}

	@Override
	protected void read(InputStream in) throws IOException, ParsingException {
		time = new byte[4];
		readComplete(in, time);

		stream = new byte[4];
		readComplete(in, stream);

		services = new byte[8];
		readComplete(in, stream);

		ip = new byte[16];
		readComplete(in, ip);

		port = new byte[2];
		readComplete(in, port);

		InetAddress addr = getIp();

		if (addr.isAnyLocalAddress() || addr.isMulticastAddress()) {
			throw new ParsingException("IP is local or multicast!");
		}

		boolean isNull = true;

		for (byte b : addr.getAddress()) {
			if (b != 0) {
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
			b.write(time);
			b.write(stream);
			b.write(services);
			b.write(ip);
			b.write(port);
		} catch (IOException e) {
			LOG.log(Level.SEVERE, "Could not write bytes!", e);
			System.exit(1);
		}

		return b.toByteArray();
	}

	public int getTime() {
		return Util.getInt(time);
	}

	public int getStream() {
		return Util.getInt(stream);
	}

	public long getServices() {
		return Util.getLong(services);
	}

	public InetAddress getIp() {
		try {
			if (isIpv4()) {
				return InetAddress.getByAddress(Arrays.copyOfRange(ip, 12, 15));
			} else {
				return InetAddress.getByAddress(ip);
			}
		} catch (UnknownHostException e) {
			return null;
		}
	}

	/**
	 * Returns true if the ip-address is an IPv4 address, false if it is an IPv6
	 * address.
	 * 
	 * @return True if the ip-address is an IPv4 address, false if it is an IPv6
	 *         address.
	 */
	public boolean isIpv4() {
		byte[] prefix = new byte[12];
		prefix[10] = prefix[11] = -1;

		return Arrays.equals(Arrays.copyOf(ip, 12), prefix);
	}

	public int getPort() {
		return Util.getInt(new byte[] { 0, 0, port[0], port[1] });
	}
}