package sibbo.bitmessage.network.protocol;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import sibbo.bitmessage.Options;

/**
 * A message to request inventory objects.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 */
public class GetdataMessage extends P2PMessage {
	private static final Logger LOG = Logger.getLogger(InvMessage.class.getName());

	/** The command string for this message type. */
	public static final String COMMAND = "getdata";

	/** The inventory vectors. */
	private List<InventoryVectorMessage> inv;

	/**
	 * Creates a new getdata message with the given inventory vectors.
	 * 
	 * @param inv
	 *            The inventory vectors.
	 */
	public GetdataMessage(Collection<? extends InventoryVectorMessage> inv, MessageFactory factory) {
		super(factory);

		this.inv = new ArrayList<>(inv);
	}

	/**
	 * {@link Message#Message(InputBuffer, MessageFactory)}
	 */
	public GetdataMessage(InputBuffer b, MessageFactory factory) throws IOException, ParsingException {
		super(b, factory);
	}

	@Override
	public String getCommand() {
		return COMMAND;
	}

	@Override
	protected void read(InputBuffer b) throws IOException, ParsingException {
		VariableLengthIntegerMessage vLength = getMessageFactory().parseVariableLengthIntegerMessage(b);
		b = b.getSubBuffer(vLength.length());
		long length = vLength.getLong();

		if (length < 0 || length > Options.getInstance().getInt("protocol.maxInvLength")) {
			throw new ParsingException("Too much inventory vectors: " + length);
		}

		inv = new ArrayList<>((int) length);

		for (int i = 0; i < length; i++) {
			InventoryVectorMessage ivm = getMessageFactory().parseInventoryVectorMessage(b);
			inv.add(ivm);
			b = b.getSubBuffer(ivm.length());
		}
	}

	@Override
	public byte[] getBytes() {
		ByteArrayOutputStream b = new ByteArrayOutputStream();

		try {
			b.write(getMessageFactory().createVariableLengthIntegerMessage(inv.size()).getBytes());

			for (InventoryVectorMessage m : inv) {
				b.write(m.getBytes());
			}
		} catch (IOException e) {
			LOG.log(Level.SEVERE, "Could not write bytes!", e);
			System.exit(1);
		}

		return b.toByteArray();
	}

	public List<InventoryVectorMessage> getInventoryVectors() {
		return new ArrayList<>(inv);
	}
}