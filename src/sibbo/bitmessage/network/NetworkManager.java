package sibbo.bitmessage.network;

import java.util.ArrayList;
import java.util.List;
import java.util.Vector;
import java.util.logging.Logger;

import sibbo.bitmessage.crypt.BMAddress;
import sibbo.bitmessage.data.Datastore;
import sibbo.bitmessage.network.protocol.InventoryVectorMessage;
import sibbo.bitmessage.network.protocol.MsgMessage;
import sibbo.bitmessage.network.protocol.NetworkAddressMessage;
import sibbo.bitmessage.network.protocol.POWMessage;

/**
 * Manages the operation of this bitmessage node. It is responsible for all
 * communication with other nodes.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 */
public class NetworkManager implements ConnectionListener, Runnable {
	private static final Logger LOG = Logger.getLogger(NetworkManager.class
			.getName());

	/**
	 * Contains all connections managed by this object.<br />
	 * Thread-safe
	 */
	private List<Connection> connections = new Vector<>();

	/**
	 * The objects that listen for network status changes.<br />
	 * Thread-safe
	 */
	private List<NetworkListener> listeners = new Vector<>();

	/** The datastore that makes all data persistent. */
	private Datastore datastore;

	/**
	 * The parser to parse new objects. This is used to prevent timing attacks
	 * on the network manager thread.
	 */
	private ObjectParser objectParser;

	/**
	 * Creates a new network manager operating on the datastore at the given
	 * path.
	 * 
	 * @param datastore The name of the datastore.
	 */
	public NetworkManager(String datastoreName) {
		this.datastore = new Datastore(datastoreName);
		objectParser = new ObjectParser(new ArrayList<BMAddress>());

		new Thread(this, "Network Manager").start();
	}

	/**
	 * Adds the given NetworkListener.
	 * 
	 * @param l The listener to add.
	 */
	public void addNetworkListener(NetworkListener l) {
		listeners.add(l);
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
	public void connectionAborted(Connection c) {
		connections.remove(c);
		fireConnectionCountChanged(connections.size(), false);
	}

	@Override
	public void receivedObject(POWMessage m) {
		if (datastore.put(m) && m.getCommand().equals(MsgMessage.COMMAND)) {
			objectParser.parse((MsgMessage) m);
		}
	}

	@Override
	public void receivedNodes(List<? extends NetworkAddressMessage> list) {
		// TODO Auto-generated method stub

	}

	@Override
	public void advertisedObjects(List<InventoryVectorMessage> inventoryVectors) {
		// TODO Auto-generated method stub

	}

	@Override
	public void run() {
		// TODO Auto-generated method stub

	}
}