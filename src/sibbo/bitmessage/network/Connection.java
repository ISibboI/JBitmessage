package sibbo.bitmessage.network;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.LinkedList;
import java.util.Objects;
import java.util.Queue;
import java.util.logging.Level;
import java.util.logging.Logger;

import sibbo.bitmessage.Options;
import sibbo.bitmessage.network.protocol.BaseMessage;
import sibbo.bitmessage.network.protocol.NetworkAddressMessage;
import sibbo.bitmessage.network.protocol.NodeServicesMessage;
import sibbo.bitmessage.network.protocol.P2PMessage;
import sibbo.bitmessage.network.protocol.POWMessage;
import sibbo.bitmessage.network.protocol.ParsingException;
import sibbo.bitmessage.network.protocol.SimpleNetworkAddressMessage;
import sibbo.bitmessage.network.protocol.VerackMessage;
import sibbo.bitmessage.network.protocol.VersionMessage;

/**
 * A network connection to a single node.<br />
 * <br />
 * Operation modes:
 * <ul>
 * <li>FOLLOW_STREAM: Follows the given stream and its parent and child streams.
 * </li>
 * </ul>
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 */
public class Connection implements Runnable {
	private static final Logger LOG = Logger.getLogger(Connection.class
			.getName());

	/** The remote address. */
	private InetAddress address;

	/** The remote port. */
	private int port;

	/** The streams to follow. */
	private long[] streams;

	/** The streams the remote nodes follows. */
	private long[] remoteStreams;

	/** The listener to inform if something happens. */
	private ConnectionListener listener;

	/** Holds objects that should be advertised as soon as possible. */
	private Queue<P2PMessage> objectsToAdvertise = new LinkedList<>();

	/** If true, the connection is aborted as fast as possible. */
	private volatile boolean stop = false;

	/** If true, there is a thread operating on this object. */
	private boolean running = false;

	/** The socket used for the connection. */
	private Socket s;

	/** True if we have verified the remote node with a verack message. */
	private boolean remoteVerified = false;

	/** True if the remote node has verified us with a verack message. */
	private boolean localVerified = false;

	/** Random nonce to detect connections to self. */
	private long nonce;

	/**
	 * True if this connection acts as a client, meaning that it sends its
	 * version first.
	 */
	private boolean client;

	/**
	 * Creates and starts a new Connection with the agenda FOLLOW_STREAM.
	 * 
	 * @param address The address to connect to.
	 * @param port The remote port.
	 * @param stream The stream to follow.
	 * @param listener The listener to inform if something interesting happens,
	 *            like the connection could not be established or we received
	 *            new objects.
	 * @param nonce Random nonce to detect connections to self. Must be the same
	 *            for every connection of the program.
	 */
	public Connection(InetAddress address, int port, long stream,
			ConnectionListener listener, long nonce) {
		Objects.requireNonNull(address, "address must not be null.");
		Objects.requireNonNull(listener, "listener must not be null.");

		if (port <= 0 || port > 65535) {
			throw new IllegalArgumentException("port out of range: " + port);
		}

		this.address = address;
		this.port = port;
		streams = Streams.getPerimeter(stream);
		this.listener = listener;
		this.nonce = nonce;
		client = true;

		start();
	}

	/**
	 * Creates and starts a new Connection with the agenda FOLLOW_STREAM.
	 * 
	 * @param s The connection socket.
	 * @param stream The stream to follow.
	 * @param listener The listener to inform if something interesting happens,
	 *            like the connection could not be established or we received
	 *            new objects.
	 * @param nonce Random nonce to detect connections to self. Must be the same
	 *            for every connection of the program.
	 */
	public Connection(Socket s, long stream, ConnectionListener listener,
			long nonce) {
		Objects.requireNonNull(s, "s must not be null");

		this.s = s;
		this.listener = listener;
		this.nonce = nonce;
		address = s.getInetAddress();
		port = s.getPort();
		streams = Streams.getPerimeter(stream);
		client = false;

		start();
	}

	private synchronized void start() {
		if (running) {
			throw new IllegalStateException(
					"This connection is already started.");
		} else {
			running = true;
		}

		new Thread(this, "Connection: " + address.getHostAddress() + ":" + port)
				.start();
	}

	@Override
	public void run() {
		InputStream in;
		OutputStream out;

		// If there is no connection, connect.
		if (s == null) {
			s = new Socket();

			try {
				s.connect(new InetSocketAddress(address, port), Options
						.getInstance().getInt("network.connectTimeout"));
				s.setSoTimeout(Options.getInstance().getInt("network.timeout"));
				s.setTcpNoDelay(true);
			} catch (IOException e) {
				LOG.log(Level.INFO,
						"Could not connect to " + address.getHostAddress()
								+ ":" + port + " because: " + e.getMessage());
				close(s);
				listener.couldNotConnect(this);
				return;
			}
		}

		// Create the streams.
		try {
			in = s.getInputStream();
			out = s.getOutputStream();
		} catch (IOException e) {
			LOG.log(Level.INFO,
					"Could open streams " + address.getHostAddress() + ":"
							+ port + " because: " + e.getMessage());
			close(s);
			listener.connectionAborted(this);
			return;
		}

		if (client) {
			try {
				sendVersion(out);
			} catch (IOException e) {
				LOG.log(Level.INFO, "Connection to " + address.getHostAddress()
						+ ":" + port + " aborted: " + e.getMessage());
				close(s);
				listener.connectionAborted(this);
				return;
			}
		}

		// Parse an incoming message.
		try {
			while (!stop) {
				BaseMessage b = new BaseMessage(in, Options.getInstance()
						.getInt("protocol.maxMessageLength"));

				P2PMessage m = b.getPayload();

				switch (m.getCommand()) {
					case "version":
						receiveVersion((VersionMessage) m, out);
						break;

					case "verack":
						receiveVerack((VerackMessage) m, out);
						break;

					default:
						LOG.log(Level.WARNING,
								"Unknown command: " + m.getCommand());
						close(s);
						listener.connectionAborted(this);
						return;
				}
			}
		} catch (IOException e) {
			LOG.log(Level.INFO, "Connection to " + address.getHostAddress()
					+ ":" + port + " aborted: " + e.getMessage());
			close(s);
			listener.connectionAborted(this);
			return;
		} catch (ParsingException e) {
			LOG.log(Level.WARNING, "Parsing error", e);
			close(s);
			listener.connectionAborted(this);
			return;
		}
	}

	private void receiveVerack(VerackMessage m, OutputStream out) {
		localVerified = true;
	}

	private void receiveVersion(VersionMessage m, OutputStream out)
			throws IOException {
		VersionMessage version = m;
		LOG.log(Level.INFO, "Remote user agent: " + version.getUserAgent());

		if (version.getNonce() == nonce) {
			LOG.log(Level.WARNING, "Connected to self!");
			close(s);
			listener.connectionAborted(this);
		}

		remoteStreams = version.getStreams();

		sendVerack(out);
		remoteVerified = true;

		if (!client) {
			sendVersion(out);
		}
	}

	private void sendVerack(OutputStream out) throws IOException {
		out.write(new BaseMessage(new VerackMessage()).getBytes());
	}

	private void sendVersion(OutputStream out) throws IOException {
		try {
			NodeServicesMessage services = new NodeServicesMessage(Options
					.getInstance().getLong("protocol.services"));
			SimpleNetworkAddressMessage receiver = new SimpleNetworkAddressMessage(
					new NodeServicesMessage(Options.getInstance().getLong(
							"protocol.remoteServices")), address, port);
			SimpleNetworkAddressMessage sender = new SimpleNetworkAddressMessage(
					services, InetAddress.getByName("127.0.0.1"), Options
							.getInstance().getInt("network.listenPort"));

			VersionMessage version = new VersionMessage(services,
					System.currentTimeMillis() / 1000, receiver, sender, nonce,
					Options.getInstance().getString("network.userAgent"),
					streams);
			BaseMessage m = new BaseMessage(version);

			out.write(m.getBytes());
		} catch (UnknownHostException e) {
			LOG.log(Level.SEVERE, "Localhost is unknown!", e);
			System.exit(1);
		}
	}

	private void close(Socket s) {
		try {
			s.close();
		} catch (IOException e) {
			LOG.log(Level.FINE, "Could not close socket.", e);
		}
	}

	public static void main(String[] args) throws UnknownHostException {
		Connection c = new Connection(InetAddress.getByName("127.0.0.1"), 8444,
				1L, new ConnectionListener() {
					@Override
					public void receivedObject(POWMessage m) {
						System.out.println("receivedObject()");
					}

					@Override
					public void receivedNode(NetworkAddressMessage[] m) {
						System.out.println("receivedNode()");
					}

					@Override
					public void couldNotConnect(Connection c) {
						System.out.println("couldNotConnect()");
					}

					@Override
					public void connectionAborted(Connection c) {
						System.out.println("connectionAborted()");
					}
				}, 541373894);

	}
}