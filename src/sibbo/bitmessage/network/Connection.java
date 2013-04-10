package sibbo.bitmessage.network;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Queue;
import java.util.logging.Level;
import java.util.logging.Logger;

import sibbo.bitmessage.Options;
import sibbo.bitmessage.data.Datastore;
import sibbo.bitmessage.network.protocol.AddrMessage;
import sibbo.bitmessage.network.protocol.BaseMessage;
import sibbo.bitmessage.network.protocol.GetdataMessage;
import sibbo.bitmessage.network.protocol.InvMessage;
import sibbo.bitmessage.network.protocol.InventoryVectorMessage;
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
 * <li>FIND_STREAM: Follows all given streams, does not send inv or getdata
 * messages.</li>
 * </ul>
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 */
public class Connection implements Runnable {
	private static final Logger LOG = Logger.getLogger(Connection.class
			.getName());

	/** The operation mode of this connection. */
	private Agenda agenda;

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

	/** Holds hashes of objects that should be advertised as soon as possible. */
	private Queue<InventoryVectorMessage> invBuffer = new LinkedList<>();

	/** Nodes that should be advertised. */
	private Queue<NetworkAddressMessage> nodeBuffer = new LinkedList<>();

	/** Holds hashes of objects that should be requested. */
	private Queue<InventoryVectorMessage> requestBuffer = new LinkedList<>();

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

	/** True if all initially known addresses have been sent. */
	private boolean addrSent;

	/** The datastore that stores the nodes and objects for this node. */
	private Datastore datastore;

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

	/**
	 * Schedules the advertising of all given objects. If the agenda of this
	 * connection is FIND_STREAM, this method does nothing.
	 * 
	 * @param c The hashes of the objects to advertise.
	 */
	public void advertiseObjects(Collection<? extends InventoryVectorMessage> c) {
		if (agenda != Agenda.FIND_STREAM) {
			synchronized (invBuffer) {
				invBuffer.addAll(c);
			}
		}
	}

	/**
	 * Schedules the advertising of all given nodes. If the agenda of this
	 * connection is FIND_STREAM, this method does nothing.
	 * 
	 * @param c The nodes to advertise.
	 */
	public void advertiseNodes(Collection<? extends NetworkAddressMessage> c) {
		if (agenda != Agenda.FIND_STREAM) {
			synchronized (nodeBuffer) {
				nodeBuffer.addAll(c);
			}
		}
	}

	/**
	 * Schedules the requesting of all given objects. If the agenda of this
	 * connection is FIND_STREAM, this method does nothing.
	 * 
	 * @param c The hashes of the objects to request.
	 */
	public void requestObjects(Collection<? extends InventoryVectorMessage> c) {
		if (agenda != Agenda.FIND_STREAM) {
			synchronized (requestBuffer) {
				requestBuffer.addAll(c);
			}
		}
	}

	/**
	 * Starts this connection.
	 */
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

		// Send the version message if we are the one that connected.
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
				BaseMessage b = null;

				try {
					b = new BaseMessage(in, Options.getInstance().getInt(
							"protocol.maxMessageLength"));
				} catch (SocketTimeoutException e) {
					sendMessages(out);
					continue;
				}

				P2PMessage m = b.getPayload();

				LOG.log(Level.FINE, "Received: " + b.getCommand());

				switch (m.getCommand()) {
					case VersionMessage.COMMAND:
						receiveVersion((VersionMessage) m, out);
						break;

					case VerackMessage.COMMAND:
						receiveVerack((VerackMessage) m, out);
						break;

					case AddrMessage.COMMAND:
						receiveAddr((AddrMessage) m, out);
						break;

					case InvMessage.COMMAND:
						receiveInv((InvMessage) m, out);
						break;

					case GetdataMessage.COMMAND:
						receiveGetdata((GetdataMessage) m, out);
						break;

					default:
						if (m instanceof POWMessage) {
							listener.receivedObject((POWMessage) m, this);
						} else {
							LOG.log(Level.WARNING,
									"Unknown command: " + m.getCommand());
							close(s);
							listener.connectionAborted(this);
							return;
						}
				}

				sendMessages(out);
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

		close(s);
		listener.connectionAborted(this);
	}

	private void receiveGetdata(GetdataMessage m, OutputStream out)
			throws IOException {
		List<POWMessage> objects = datastore
				.getObjects(m.getInventoryVectors());

		for (POWMessage object : objects) {
			out.write(new BaseMessage(object).getBytes());
		}
	}

	private void receiveInv(InvMessage m, OutputStream out) throws IOException {
		listener.advertisedObjects(m.getInventoryVectors(), this);
	}

	private void sendGetdata(List<InventoryVectorMessage> toSend,
			OutputStream out) throws IOException {
		GetdataMessage m = new GetdataMessage(toSend);
		BaseMessage b = new BaseMessage(m);
		out.write(b.getBytes());
		LOG.fine("Sent: getdata (" + toSend.size() + ")");
	}

	private void sendMessages(OutputStream out) throws IOException {
		if (!(localVerified && remoteVerified)) {
			return;
		}

		sendAddr(out);

		synchronized (invBuffer) {
			if (invBuffer.size() > 0) {
				int messageSize = invBuffer.size();

				if (messageSize > Options.getInstance().getInt(
						"protocol.maxInvLength")) {
					messageSize = Options.getInstance().getInt(
							"protocol.maxInvLength");
				}

				ArrayList<InventoryVectorMessage> toSend = new ArrayList<>(
						messageSize);
				for (int i = 0; i < messageSize; i++) {
					toSend.add(invBuffer.poll());
				}

				sendInv(toSend, out);
			}
		}

		synchronized (nodeBuffer) {
			if (nodeBuffer.size() > 0) {
				int messageSize = nodeBuffer.size();

				if (messageSize > Options.getInstance().getInt(
						"protocol.maxAddrLength")) {
					messageSize = Options.getInstance().getInt(
							"protocol.maxAddrLength");
				}

				ArrayList<NetworkAddressMessage> toSend = new ArrayList<>(
						messageSize);
				for (int i = 0; i < messageSize; i++) {
					toSend.add(nodeBuffer.poll());
				}

				sendAddr(toSend, out);
			}
		}

		synchronized (requestBuffer) {
			if (requestBuffer.size() > 0) {
				int messageSize = requestBuffer.size();

				if (messageSize > Options.getInstance().getInt(
						"protocol.maxInvLength")) {
					messageSize = Options.getInstance().getInt(
							"protocol.maxInvLength");
				}

				ArrayList<InventoryVectorMessage> toSend = new ArrayList<>(
						messageSize);
				for (int i = 0; i < messageSize; i++) {
					toSend.add(requestBuffer.poll());
				}

				sendGetdata(toSend, out);
			}
		}
	}

	private void sendAddr(ArrayList<NetworkAddressMessage> toSend,
			OutputStream out) throws IOException {
		out.write(new BaseMessage(new AddrMessage(toSend)).getBytes());

		LOG.fine("Sent: addr (" + toSend.size() + ")");
	}

	private void sendInv(ArrayList<InventoryVectorMessage> toSend,
			OutputStream out) throws IOException {
		out.write(new BaseMessage(new InvMessage(toSend)).getBytes());

		LOG.fine("Sent: inv (" + toSend.size() + ")");
	}

	private void receiveAddr(AddrMessage m, OutputStream out)
			throws IOException {
		listener.receivedNodes(m.getAddresses(), this);
	}

	private void sendAddr(OutputStream out) throws IOException {
		if (addrSent) {
			return;
		} else {
			addrSent = true;
		}

		List<NetworkAddressMessage> addresses = datastore
				.getNodes(remoteStreams);

		while (!addresses.isEmpty()) {
			List<NetworkAddressMessage> tmp = new ArrayList<>(1000);

			for (int i = 0; i < 1000 && !addresses.isEmpty(); i++) {
				tmp.add(addresses.get(addresses.size() - 1));
			}

			AddrMessage addr = new AddrMessage(tmp);
			BaseMessage b = new BaseMessage(addr);
			out.write(b.getBytes());

			LOG.fine("Sent: addr (" + tmp.size() + ")");
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
		LOG.fine("Sent: verack");
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
			LOG.fine("Sent: version");
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

	public InetAddress getAddress() {
		return address;
	}

	public int getPort() {
		return port;
	}

	/**
	 * Stops the connection as fast as possible.
	 */
	public void stop() {
		stop = true;
	}

	public void advertiseObject(InventoryVectorMessage inventoryVector) {
		synchronized (invBuffer) {
			invBuffer.add(inventoryVector);
		}
	}

	// public static void main(String[] args) throws UnknownHostException {
	// LoggingInitializer.initializeLogging();
	//
	// Connection c = new Connection(InetAddress.getByName("127.0.0.1"), 8444,
	// 1L, new ConnectionListener() {
	// @Override
	// public void receivedObject(POWMessage m) {
	// System.out.println("receivedObject()");
	// }
	//
	// @Override
	// public void receivedNodes(
	// List<? extends NetworkAddressMessage> m) {
	// System.out.println("receivedNodes()");
	// }
	//
	// @Override
	// public void couldNotConnect(Connection c) {
	// System.out.println("couldNotConnect()");
	// }
	//
	// @Override
	// public void connectionAborted(Connection c) {
	// System.out.println("connectionAborted()");
	// }
	//
	// @Override
	// public void advertisedObjects(
	// List<InventoryVectorMessage> inventoryVectors) {
	// System.out.println("advertisedObjects()");
	// }
	// }, 541373894);
	// }
}