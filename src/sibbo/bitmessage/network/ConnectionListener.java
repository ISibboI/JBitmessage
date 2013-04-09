package sibbo.bitmessage.network;

import java.util.List;

import sibbo.bitmessage.network.protocol.InventoryVectorMessage;
import sibbo.bitmessage.network.protocol.NetworkAddressMessage;
import sibbo.bitmessage.network.protocol.POWMessage;

/**
 * A listener that is informed if something happens during a connection to a
 * node.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 * 
 */
public interface ConnectionListener {
	/**
	 * The given connection was not able to connect to its target.
	 * 
	 * @param c A connection.
	 */
	void couldNotConnect(Connection c);

	/**
	 * The connection to the target was canceled.
	 * 
	 * @param c A connection.
	 */
	void connectionAborted(Connection c);

	/**
	 * The connection received a new object from its target.
	 * 
	 * @param m An object.
	 */
	void receivedObject(POWMessage m);

	/**
	 * The connection received a list of new nodes.
	 * 
	 * @param list A list of nodes.
	 */
	void receivedNodes(List<? extends NetworkAddressMessage> list);

	/**
	 * The connection received a list of object hashes.
	 * 
	 * @param inventoryVectors A list of object hashes.
	 */
	void advertisedObjects(List<InventoryVectorMessage> inventoryVectors);
}