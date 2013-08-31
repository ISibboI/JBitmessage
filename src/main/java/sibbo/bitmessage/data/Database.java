package sibbo.bitmessage.data;

import java.util.logging.Logger;

import sibbo.bitmessage.network.protocol.InventoryVectorMessage;
import sibbo.bitmessage.network.protocol.POWMessage;

/**
 * Class that manages a connection to a database. It creates several prepared
 * statements to make operations fast and secure.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 * 
 */
public class Database {
	/**
	 * Creates a new database with the given name or connects to the existing
	 * one. Note that the user used for connecting must have the rights to
	 * create a new database if it is not already created.
	 * 
	 * @param path
	 *            The name of the database.
	 */
	public Database(String name) {
		// TODO Auto-generated constructor stub
	}

	private static final Logger LOG = Logger.getLogger(Database.class.getName());

	/**
	 * Reads the object with the given hash from the database.
	 * 
	 * @param m
	 *            The hash.
	 * @return The object with the given hash or null, if there is no object
	 *         with the given hash.
	 */
	public POWMessage getObject(InventoryVectorMessage m) {
		return null;
		// TODO Auto-generated method stub

	}
}
