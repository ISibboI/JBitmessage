package sibbo.bitmessage.network;

import java.util.Collection;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Vector;
import java.util.logging.Logger;

import sibbo.bitmessage.Options;
import sibbo.bitmessage.data.Datastore;
import sibbo.bitmessage.network.protocol.InventoryVectorMessage;
import sibbo.bitmessage.network.protocol.MsgMessage;
import sibbo.bitmessage.network.protocol.NetworkAddressMessage;
import sibbo.bitmessage.network.protocol.POWMessage;
import sibbo.bitmessage.network.protocol.Util;

/**
 * Manages the operation of this bitmessage node. It is responsible for all
 * communication with other nodes.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 */
public class NetworkManager implements ConnectionListener, Runnable {
	private static final Logger LOG = Logger.getLogger(NetworkManager.class.getName());

	/**
	 * Contains all connections managed by this object.<br />
	 * Thread-safe
	 */
	private final List<Connection> connections = new Vector<>();

	/**
	 * The objects that listen for network status changes.<br />
	 * Thread-safe
	 */
	private final List<NetworkListener> listeners = new Vector<>();

	/** The datastore that makes all data persistent. */
	private final Datastore datastore;

	/** Contains all objects that are currently requested from a node. */
	// Note that this is a bad method to ensure that we get all objects but
	// don't get anything twice. If someone sends an inv but never responds to a
	// getdata and keeps connected, the respective objects will be blocked and
	// can only be received if the network manager is restarted.
	private final Map<InventoryVectorMessage, Connection> alreadyRequested = new Hashtable<>();

	/**
	 * The parser to parse new objects. This is used to prevent timing attacks
	 * on the network manager thread.
	 */
	private final ObjectParser objectParser;

	/** If this is true, the network manager stops as fast as possible. */
	private volatile boolean stop;

	/**
	 * True if someone connected to us. That means that we are reachable from
	 * outside.
	 */
	private boolean activeMode;

	/** A random nonce to detect connections to self. */
	private final long nonce;

	/**
	 * Creates a new network manager operating on the datastore at the given
	 * path.
	 * 
	 * @param datastore
	 *            The name of the datastore.
	 */
	public NetworkManager(String datastoreName) {
		this.datastore = new Datastore(datastoreName);
		objectParser = new ObjectParser(datastore.getAddresses());

		Random r = new Random();
		byte[] nonce = new byte[8];
		r.nextBytes(nonce);
		this.nonce = Util.getLong(nonce);

		new Thread(this, "Network Manager").start();
	}

	/**
	 * Adds the given NetworkListener.
	 * 
	 * @param l
	 *            The listener to add.
	 */
	public void addNetworkListener(NetworkListener l) {
		listeners.add(l);
	}

	@Override
	public void advertisedObjects(List<InventoryVectorMessage> inventoryVectors, Connection c) {
		Collection<InventoryVectorMessage> toSend = datastore.filterObjectsThatWeAlreadyHave(inventoryVectors);
		toSend.removeAll(alreadyRequested.keySet());

		for (InventoryVectorMessage i : toSend) {
			alreadyRequested.put(i, c);
		}

		c.requestObjects(toSend);
	}

	@Override
	public void connectionAborted(Connection c) {
		connections.remove(c);

		for (InventoryVectorMessage i : new HashSet<>(alreadyRequested.keySet())) {
			if (alreadyRequested.get(i) == c) {
				alreadyRequested.remove(i);
			}
		}

		fireConnectionCountChanged(connections.size(), false);
	}

	@Override
	public void couldNotConnect(Connection c) {
		connections.remove(c);
		datastore.removeNodeIfOld(c.getAddress(), c.getPort());
		fireConnectionCountChanged(connections.size(), false);
	}

	/**
	 * Calls connectionCountChanged() for all NetworkListeners.
	 */
	private void fireConnectionCountChanged(int connectionCount, boolean up) {
		for (NetworkListener l : listeners) {
			l.connectionCountChanged(connectionCount, up);
		}
	}

	@Override
	public void receivedNodes(List<NetworkAddressMessage> list, Connection c) {
		Collection<NetworkAddressMessage> toSend = datastore.putAll(list);

		for (Connection con : connections) {
			if (con != c) {
				con.advertiseNodes(toSend);
			}
		}
	}

	@Override
	public void receivedObject(POWMessage m, Connection c) {
		alreadyRequested.remove(m.getInventoryVector());

		if (datastore.put(m)) {
			for (Connection con : connections) {
				if (con != c) {
					con.advertiseObject(m.getInventoryVector());
				}
			}

			if (m.getCommand().equals(MsgMessage.COMMAND)) {
				objectParser.parse((MsgMessage) m, m.getMessageFactory());
			}
		}
	}

	@Override
	public void run() {
		while (!stop) {
			if ((activeMode && connections.size() < Options.getInstance().getInt("network.activeMode.maxConnections"))
					|| (!activeMode && connections.size() < Options.getInstance().getInt(
							"network.passiveMode.maxConnections"))) {
				NetworkAddressMessage m = datastore.getRandomNode(1); // TODO
																		// Add
																		// multi
																		// stream
																		// management
				Connection c = new Connection(m.getIp(), m.getPort(), m.getStream(), this, nonce);
				connections.add(c);
			}

			try {
				Thread.sleep(10);
			} catch (InterruptedException e) {
			}
		}
	}

	/**
	 * Stops the network manager as fast as possible. This also stops all
	 * connections, the datastore and other childs.
	 */
	public void stop() {
		stop = true;

		objectParser.stop();
		datastore.stop();

		for (Connection c : connections) {
			c.stop();
		}
	}
}