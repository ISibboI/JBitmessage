package sibbo.bitmessage.network;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Queue;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;

import sibbo.bitmessage.crypt.BMAddress;
import sibbo.bitmessage.crypt.CryptManager;
import sibbo.bitmessage.crypt.KeyDataPair;
import sibbo.bitmessage.network.protocol.InputBuffer;
import sibbo.bitmessage.network.protocol.MsgMessage;
import sibbo.bitmessage.network.protocol.ParsingException;
import sibbo.bitmessage.network.protocol.UnencryptedMessageDataMessage;

/**
 * Tries to decrypt msg messages.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 * 
 */
public class ObjectParser implements Runnable {
	private static final Logger LOG = Logger.getLogger(ObjectParser.class
			.getName());

	/** Messages to decrypt. */
	private Queue<MsgMessage> queue = new LinkedList<>();

	/** The listeners that have to be informed if a new message was received. */
	private List<MessageListener> listeners = new Vector<>();

	/** Contains all addresses that can be used for decryption. */
	private List<BMAddress> addresses = new ArrayList<>();

	/** True if the object parser should stop as fast as possible. */
	private volatile boolean stop;

	/**
	 * Creates a new object parser with the given addresses.
	 * 
	 * @param addresses
	 *            The addresses.
	 */
	public ObjectParser(Collection<BMAddress> addresses) {
		this.addresses.addAll(addresses);
	}

	@Override
	public void run() {
		while (!stop) {
			MsgMessage m = null;

			synchronized (queue) {
				if (queue.size() > 0) {
					m = queue.poll();
				}
			}

			if (m == null) {
				try {
					Thread.sleep(100);
				} catch (InterruptedException e) {
					LOG.log(Level.WARNING, "Sleeping interrupted!", e);
				}
			} else {
				KeyDataPair kd = null;
				BMAddress addr = null;

				for (BMAddress a : addresses) {
					kd = CryptManager.getInstance().tryDecryption(new KeyDataPair(
							CryptManager.getInstance()
									.createKeyPairWithPrivateKey(
											a.getPrivateEncryptionKey()),
							m.getEncrypted()));

					if (kd != null) {
						addr = a;
						break;
					}
				}

				if (kd != null) {
					try {
						UnencryptedMessageDataMessage u = new UnencryptedMessageDataMessage(
								new InputBuffer(new ByteArrayInputStream(
										kd.getData()), kd.getData().length,
										kd.getData().length));

						if (!Arrays.equals(u.getDestinationRipe(),
								addr.getRipe())) {
							LOG.log(Level.WARNING,
									"Received message that contained a wrong destination ripe.");
						} else {
							fireMessageReceived(u);
						}
					} catch (IOException e) {
						LOG.log(Level.SEVERE,
								"Could not read from local byte[]!", e);
					} catch (ParsingException e) {
						LOG.log(Level.WARNING,
								"Received a message that we could decrypt but not parse.",
								e);
					}

				}
			}
		}
	}

	private void fireMessageReceived(UnencryptedMessageDataMessage u) {
		for (MessageListener l : listeners) {
			l.messageReceived(u);
		}
	}

	/**
	 * Schedules the parsing of the given message.
	 * 
	 * @param m
	 *            The message to parse.
	 */
	public void parse(MsgMessage m) {
		synchronized (queue) {
			queue.add(m);
		}
	}

	/**
	 * Stops the object parser as fast as possible.
	 */
	public void stop() {
		stop = true;
	}

	/**
	 * Adds the given address to the set of addresses.
	 * 
	 * @param address
	 *            The address to add.
	 */
	public void addPrivateKey(BMAddress address) {
		Objects.requireNonNull(address, "address must not be null.");

		addresses.add(address);
	}
}