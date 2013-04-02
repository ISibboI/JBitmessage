package sibbo.bitmessage.protocol;

import java.util.logging.Logger;

/**
 * Contains constants for a bitfield describing the features of a node.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 */
public final class NodeServices {
	private static final Logger LOG = Logger.getLogger(NodeServices.class
			.getName());

	public static final long NODE_NETWORK = 1;

	/** Utility class. */
	private NodeServices() {
	}

	public static boolean checkService(long node, long service) {
		return (node & service) != 0;
	}
}
