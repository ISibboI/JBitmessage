package sibbo.bitmessage.network.protocol;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import sibbo.bitmessage.Options;

/**
 * A message to advertise inventory objects.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 */
public class InvMessage extends P2PMessage {
	private static final Logger LOG = Logger.getLogger(InvMessage.class
			.getName());

	/** The command string for this message type. */
	public static final String COMMAND = "inv";

	/** The inventory vectors. */
	private InventoryVectorMessage[] inv;

	/**
	 * Creates a new inv message with the given inventory vectors.
	 * 
	 * @param inv The inventory vectors.
	 */
	public InvMessage(InventoryVectorMessage[] inv) {
		this.inv = inv;
	}

	@Override
	public String getCommand() {
		return COMMAND;
	}

	@Override
	protected void read(InputBuffer b) throws IOException, ParsingException {
		VariableLengthIntegerMessage vLength = new VariableLengthIntegerMessage(
				b);
		b = b.getSubBuffer(vLength.length());
		long length = vLength.getLong();

		if (length < 0 || length > Options.getInstance().getMaxInvLength()) {
			throw new ParsingException("Too much inventory vectors: " + length);
		}

		inv = new InventoryVectorMessage[(int) length];

		for (int i = 0; i < inv.length; i++) {
			inv[i] = new InventoryVectorMessage(b);
			b = b.getSubBuffer(inv[i].length());
		}
	}

	@Override
	public byte[] getBytes() {
		ByteArrayOutputStream b = new ByteArrayOutputStream();

		try {
			b.write(new VariableLengthIntegerMessage(inv.length).getBytes());

			for (InventoryVectorMessage m : inv) {
				b.write(m.getBytes());
			}
		} catch (IOException e) {
			LOG.log(Level.SEVERE, "Could not write bytes!", e);
			System.exit(1);
		}

		return b.toByteArray();
	}

	public InventoryVectorMessage[] getInventoryVectors() {
		return inv;
	}
}