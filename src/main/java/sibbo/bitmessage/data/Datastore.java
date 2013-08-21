package sibbo.bitmessage.data;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

import sibbo.bitmessage.crypt.BMAddress;
import sibbo.bitmessage.network.protocol.InventoryVectorMessage;
import sibbo.bitmessage.network.protocol.NetworkAddressMessage;
import sibbo.bitmessage.network.protocol.POWMessage;

/**
 * Manager for persistent data. Can cache data to reduce the load of the
 * database.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 */
public class Datastore {
	private static final Logger LOG = Logger.getLogger(Datastore.class.getName());
	/** The database. */
	private final Database database;

	/** Stores the hashes of all objects that we have. */
	private final Set<InventoryVectorMessage> localObjects = Collections
			.synchronizedSet(new HashSet<InventoryVectorMessage>());

	/** Caches objects to reduce disc activity. */
	private final Map<InventoryVectorMessage, POWMessage> objectCache = new Hashtable<>();

	/** Stores all nodes that we know. */
	private final Map<Long, Map<NetworkAddressMessage, NetworkAddressMessage>> knownNodes = new Hashtable<>();

	/** Stores all addresses we own. */
	private final Set<BMAddress> ownedAddresses = Collections.synchronizedSet(new HashSet<BMAddress>());

	/** If true, the datastore stops as fast as possible. */
	private volatile boolean stop;

	/**
	 * Creates a new datastore with the given name.
	 * 
	 * @param datastorePath
	 *            The path to the file containing the datastore.
	 */
	public Datastore(String datastoreName) {
		database = new Database(datastoreName);
	}

	/**
	 * Returns a list containing all nodes from the given list that are not
	 * present in the datastore.
	 * 
	 * @param list
	 *            The list of nodes to filter.
	 * @return A list containing only nodes that are not present in the
	 *         datastore.
	 */
	public List<NetworkAddressMessage> filterNodesThatWeAlreadyHave(List<NetworkAddressMessage> list) {
		List<NetworkAddressMessage> l = new ArrayList<>(list);

		for (Map<NetworkAddressMessage, NetworkAddressMessage> m : knownNodes.values()) {
			l.removeAll(m.values());
		}

		return l;
	}

	/**
	 * Returns a list containing all inventory vectors from the given list that
	 * represent objects we don't have.
	 * 
	 * @param inventoryVectors
	 *            The inventory vectors to check.
	 * @return The given inventory vectors without those that represent objects
	 *         that we already have.
	 */
	public List<InventoryVectorMessage> filterObjectsThatWeAlreadyHave(List<InventoryVectorMessage> inventoryVectors) {
		List<InventoryVectorMessage> l = new ArrayList<>(inventoryVectors);

		l.removeAll(localObjects);

		return l;
	}

	/**
	 * Returns all addresses that we own.
	 * 
	 * @return All addresses that we own.
	 */
	public Collection<BMAddress> getAddresses() {
		return new ArrayList<>(ownedAddresses);
	}

	/**
	 * Returns a list with all nodes that belong to one of the given streams.
	 * 
	 * @param streams
	 *            The streams.
	 * @return A list with all nodes that belong to one of the given streams.
	 */
	public List<NetworkAddressMessage> getNodes(long[] streams) {
		List<Map<NetworkAddressMessage, NetworkAddressMessage>> nodeLists = new ArrayList<>();
		int size = 0;

		for (long stream : streams) {
			Map<NetworkAddressMessage, NetworkAddressMessage> s = knownNodes.get(stream);

			if (s != null) {
				nodeLists.add(s);
				size += s.size();
			}
		}

		List<NetworkAddressMessage> l = new ArrayList<>(size);

		for (Map<NetworkAddressMessage, NetworkAddressMessage> s : nodeLists) {
			l.addAll(s.values());
		}

		return l;
	}

	/**
	 * Returns the POWMessages that belong to the given InventoryVectors
	 * (hashes).
	 * 
	 * @param inventoryVectors
	 *            The hashes.
	 * @return The objects that belong to the given hashes.
	 */
	public List<POWMessage> getObjects(List<InventoryVectorMessage> inventoryVectors) {
		List<POWMessage> objects = new ArrayList<>(inventoryVectors.size());

		for (InventoryVectorMessage m : inventoryVectors) {
			POWMessage p = objectCache.get(m);

			if (p != null) {
				objects.add(p);
			} else {
				p = database.getObject(m);

				if (p != null) {
					objects.add(p);
				}
			}
		}

		return objects;
	}

	/**
	 * Returns a random node from the datastore.
	 * 
	 * @return A random node from the datastore.
	 */
	public NetworkAddressMessage getRandomNode(long stream) {
		List<NetworkAddressMessage> nodes = new ArrayList<>(knownNodes.get(stream).keySet());

		return nodes.get((int) (Math.random() * nodes.size()));
	}

	/**
	 * Adds the given object to the datastore.
	 * 
	 * @param m
	 *            The object to add.
	 * @return True if the object was added, false if it already exists.
	 */
	public boolean put(POWMessage m) {
		InventoryVectorMessage i = m.getInventoryVector();

		if (localObjects.contains(i)) {
			objectCache.put(i, m);
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Adds all given nodes to the datastore, if they don't exist.
	 * 
	 * @param list
	 *            The nodes to add.
	 * @return A list containing all nodes that were added.
	 */
	public Collection<NetworkAddressMessage> putAll(List<NetworkAddressMessage> list) {
		List<NetworkAddressMessage> added = new ArrayList<>(list.size());

		for (NetworkAddressMessage m : list) {
			NetworkAddressMessage before = knownNodes.get(m.getStream()).put(m, m);

			if (before == null) {
				added.add(m);
			}
		}

		return added;
	}

	/**
	 * Removes the node with the given ip and port if its older than the
	 * threshold (Can be set via Options).
	 * 
	 * @param address
	 *            The address of the node.
	 * @param port
	 *            The port of the node.
	 */
	public void removeNodeIfOld(InetAddress address, int port) {
		for (Map<NetworkAddressMessage, NetworkAddressMessage> s : knownNodes.values()) {
			// NetworkAddressMessage m = s.get(new NetworkAddressMessage(1, 1,
			// new NodeServicesMessage(NodeServicesMessage.NODE_NETWORK),
			// address, port));

			// if (m.getTime() < (System.currentTimeMillis() / 1000)
			// - Options.getInstance().getInt("data.maxNodeStorageTime")) {
			// s.remove(m);
			// }

			throw new RuntimeException("Not implemented!");
		}
	}

	/**
	 * Stops the datastore as fast as possible.
	 */
	public void stop() {
		stop = true;
	}
}