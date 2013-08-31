package sibbo.bitmessage.network;

public interface NetworkListener {
	/**
	 * Called if the amount of connections the {@link NetworkManager} is holding
	 * changes.
	 * 
	 * @param count
	 *            The new amount of connections.
	 * @param up
	 *            True if the new amount is higher than the old, false if it is
	 *            lower.
	 */
	void connectionCountChanged(int count, boolean up);
}