package sibbo.bitmessage.protocol;

import java.io.IOException;
import java.util.logging.Logger;

/**
 * A message type for transmitting an integer of variable length.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 * 
 */
public class VariableLengthIntegerMessage extends Message {
	private static final Logger LOG = Logger
			.getLogger(VariableLengthIntegerMessage.class.getName());

	/** Contains the variable length integer. */
	private long n;

	/**
	 * Creates a new variable length integer message containing the given value.
	 * The length of the sent number is dependent on the height of the number.
	 * Longs are treated as uint64.
	 * 
	 * @param n The number to transmit.
	 */
	public VariableLengthIntegerMessage(long n) {
		this.n = n;
	}

	/**
	 * {@link Message#Message(InputBuffer)}
	 */
	public VariableLengthIntegerMessage(InputBuffer b) throws IOException,
			ParsingException {
		super(b);
	}

	@Override
	protected void read(InputBuffer b) throws IOException, ParsingException {
		int first = b.get(0) & 0xFF;
		byte[] varInt;

		if (first < 0xfd) {
			varInt = new byte[] { (byte) first };
		} else {
			varInt = b.get(1, 1 << first - 0xfc);
		}

		// Add a zero prefix to get a length of 8.
		byte[] tmp = new byte[8];

		for (int i = 0; i < tmp.length; i++) {
			int index = i + varInt.length - tmp.length;

			if (index >= 0) {
				tmp[i] = varInt[index];
			}
		}

		n = Util.getLong(tmp);
	}

	@Override
	public byte[] getBytes() {
		byte[] b = Util.getBytes(n);
		byte[] varInt;

		if (n < 0xfd && n >= 0) {
			varInt = new byte[] { b[7] };
		} else if (n < 0xffff && n >= 0) {
			varInt = new byte[] { (byte) 0xfd, b[6], b[7] };
		} else if (n < 0xffff_ffffL && n >= 0) {
			varInt = new byte[] { (byte) 0xfe, b[4], b[5], b[6], b[7] };
		} else {
			varInt = new byte[] { (byte) 0xff, b[0], b[1], b[2], b[3], b[4],
					b[5], b[6], b[7] };
		}

		return varInt;
	}

	public long getLong() {
		return n;
	}

	public int length() {
		if (n >= 0xFFFF_FFFFL || n < 0) {
			return 9;
		} else if (n >= 0xFFFF) {
			return 5;
		} else if (n >= 0xFD) {
			return 3;
		} else {
			return 1;
		}
	}
}
