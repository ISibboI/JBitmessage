package sibbo.bitmessage.data;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.logging.Logger;

import sibbo.bitmessage.crypt.BMAddress;
import sibbo.bitmessage.network.protocol.InventoryVectorMessage;
import sibbo.bitmessage.network.protocol.NetworkAddressMessage;
import sibbo.bitmessage.network.protocol.NodeServicesMessage;
import sibbo.bitmessage.network.protocol.POWMessage;

/**
 * Manager for persistent data. Can cache data to reduce the load of the
 * database.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 */
public class Datastore {
	private static final Logger LOG = Logger.getLogger(Datastore.class
			.getName());
	/** The database. */
	private Database database;

	/**
	 * Creates a new datastore with the given name.
	 * 
	 * @param datastorePath The path to the file containing the datastore.
	 */
	public Datastore(String datastoreName) {
		database = new Database(datastoreName);
	}

	/**
	 * Returns a list with all nodes that belong to one of the given streams.
	 * 
	 * @param streams The streams.
	 * @return A list with all nodes that belong to one of the given streams.
	 */
	public List<NetworkAddressMessage> getNodes(long[] streams) {
		return new ArrayList<>();
	}

	/**
	 * Returns a list containing all inventory vectors from the given list that
	 * represent objects we don't have.
	 * 
	 * @param inventoryVectors The inventory vectors to check.
	 * @return The given inventory vectors without those that represent objects
	 *         that we already have.
	 */
	public List<InventoryVectorMessage> filterObjectsThatWeAlreadyHave(
			List<InventoryVectorMessage> inventoryVectors) {
		return new ArrayList<>(inventoryVectors);
	}

	public List<POWMessage> getObjects(
			List<InventoryVectorMessage> inventoryVectors) {
		return new ArrayList<>();
	}

	public void removeNodeIfOld(InetAddress address, int port) {
		// TODO Auto-generated method stub
	}

	/**
	 * Adds the given object to the datastore.
	 * 
	 * @param m The object to add.
	 * @return True if the object was added, false if it already exists.
	 */
	public boolean put(POWMessage m) {
		// TODO Auto-generated method stub
		return false;
	}

	public Collection<BMAddress> getAddresses() {
		return new ArrayList<>();
	}

	/**
	 * Returns a list containing all nodes from the given list that are not
	 * present in the datastore.
	 * 
	 * @param list The list of nodes to filter.
	 * @return A list containing only nodes that are not present in the
	 *         datastore.
	 */
	public List<NetworkAddressMessage> filterNodesThatWeAlreadyHave(
			List<NetworkAddressMessage> list) {
		return list;
	}

	/**
	 * Stops the datastore as fast as possible.
	 */
	public void stop() {
		// TODO Auto-generated method stub

	}

	/**
	 * Adds all given nodes to the datastore, if they don't exist.
	 * 
	 * @param list The nodes to add.
	 * @return A list containing all nodes that were added.
	 */
	public Collection<NetworkAddressMessage> putAll(
			List<NetworkAddressMessage> list) {
		return list;
	}

	/**
	 * Returns a random node from the datastore.
	 * 
	 * @return A random node from the datastore.
	 */
	public NetworkAddressMessage getRandomNode() {
		try {
			return new NetworkAddressMessage(
					(int) (System.currentTimeMillis() / 1000), 1,
					new NodeServicesMessage(NodeServicesMessage.NODE_NETWORK),
					InetAddress.getByName("localhost"), 8444);
		} catch (UnknownHostException e) {
			throw new RuntimeException(e);
		}
	}
}