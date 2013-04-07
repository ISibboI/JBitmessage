package sibbo.bitmessage.data;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import sibbo.bitmessage.network.protocol.InventoryVectorMessage;
import sibbo.bitmessage.network.protocol.NetworkAddressMessage;

/**
 * Singleton that manages all persistent data.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 */
public class Datastore {
	private static final Logger LOG = Logger.getLogger(Datastore.class
			.getName());

	private static final Datastore instance = new Datastore();

	public static Datastore getInstance() {
		return instance;
	}

	/** Singleton. */
	private Datastore() {
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
}