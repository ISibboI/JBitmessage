package sibbo.bitmessage.network;

/**
 * A working instruction for a {@link Connection}.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 */
public enum Agenda {
	/**
	 * Just follow the given stream.
	 */
	FOLLOW_STREAM,

	/**
	 * Try to find new nodes that are nearer to the target stream as the
	 * connected node.
	 */
	FIND_STREAM
}