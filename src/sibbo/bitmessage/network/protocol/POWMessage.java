package sibbo.bitmessage.network.protocol;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import sibbo.bitmessage.crypt.CryptManager;
import sibbo.bitmessage.crypt.Digest;

/**
 * A message supertype for messages that need POW with timestamp.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 */
public abstract class POWMessage extends P2PMessage {
	private static final Logger LOG = Logger.getLogger(POWMessage.class
			.getName());

	/** The proof of work nonce. Null if the pow has not been done. */
	private byte[] nonce;

	/** The time this message was sent. */
	private int time;

	/** Caches the byte representation of the payload. */
	private byte[] payloadBytes;

	public POWMessage() {
	}

	/**
	 * {@link Message#Message(InputBuffer)}
	 */
	public POWMessage(InputBuffer b) throws IOException, ParsingException {
		super(b);
	}

	@Override
	protected final void read(InputBuffer b) throws IOException,
			ParsingException {
		nonce = b.get(0, 8);
		time = Util.getInt(b.get(8, 4));

		if (!CryptManager.checkPOW(b.get(8, b.length() - 8), nonce)) {
			throw new ParsingException("POW insufficient!");
		}

		readPayload(b.getSubBuffer(12));
	}

	/**
	 * Initializes the message reading the data from the input buffer.
	 * 
	 * @param b The input buffer to read from, must not contain POW.
	 * @throws IOException If reading from the given input buffer fails.
	 * @throws ParsingException If parsing the data fails.
	 */
	protected abstract void readPayload(InputBuffer b) throws IOException,
			ParsingException;

	@Override
	public final byte[] getBytes() {
		if (nonce == null) {
			throw new IllegalStateException("POW has not been done!");
		}

		cachePayload();
		ByteArrayOutputStream b = new ByteArrayOutputStream();

		try {
			b.write(nonce);
			b.write(Util.getBytes(time));
			b.write(payloadBytes);
		} catch (IOException e) {
			LOG.log(Level.SEVERE, "Could not write bytes!", e);
			System.exit(1);
		}

		return b.toByteArray();
	}

	private void cachePayload() {
		if (payloadBytes == null) {
			payloadBytes = getPayloadBytes();
		}
	}

	/**
	 * Does the POW for this message.<br />
	 * <b>WARNING: Takes a long time!!!</b>
	 */
	public void doPOW() {
		cachePayload();

		byte[] b = new byte[payloadBytes.length + 4];
		byte[] time = Util.getBytes(this.time);

		for (int i = 0; i < 4; i++) {
			b[i] = time[i];
		}

		for (int i = 0; i < payloadBytes.length; i++) {
			b[i + 4] = payloadBytes[i];
		}

		nonce = CryptManager.doPOW(b);
	}

	/**
	 * Creates a byte array of containing this message without POW.
	 * 
	 * @return A byte array of containing this message without POW.
	 */
	protected abstract byte[] getPayloadBytes();

	public int getTime() {
		return time;
	}

	/**
	 * Calculates the hash of this object. This method uses two rounds of sha512
	 * and returns the first 32 bytes of the sum.
	 * 
	 * @return The first 32 bytes of a 2-rounds sha512 hash of the object.
	 */
	public byte[] getHash() {
		return Digest.sha512(Digest.sha512(getBytes()), 32);
	}

	/**
	 * Returns the inventory vector describing this message.
	 * 
	 * @return The inventory vector describing this message.
	 */
	public InventoryVectorMessage getInventoryVector() {
		return new InventoryVectorMessage(getHash());
	}
}