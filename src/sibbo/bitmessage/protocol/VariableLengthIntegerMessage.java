package sibbo.bitmessage.protocol;

import java.io.IOException;
import java.io.InputStream;
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
	private byte[] varInt;

	/**
	 * Creates a new variable length integer message containing the given value.
	 * The length of the sent number is dependent on the height of the number.
	 * Longs are treated as uint64.
	 * 
	 * @param n The number to transmit.
	 */
	public VariableLengthIntegerMessage(long n) {
		byte[] b = Util.getBytes(n);

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
	}

	/**
	 * {@link Message#Message(InputStream)}
	 */
	public VariableLengthIntegerMessage(InputStream in) throws IOException,
			ParsingException {
		super(in);
	}

	@Override
	protected void read(InputStream in) throws IOException, ParsingException {
		int first = in.read();

		if (first == -1) {
			throw new IOException("End of stream.");
		} else if (first < 0xfd) {
			varInt = new byte[] { (byte) first };
		} else {
			byte[] tmp = new byte[1 << first - 0xfc];

			readComplete(in, tmp);
			varInt = new byte[tmp.length + 1];
			varInt[0] = (byte) first;

			for (int i = 0; i < tmp.length; i++) {
				varInt[i + 1] = tmp[i];
			}
		}
	}

	@Override
	public byte[] getBytes() {
		return varInt;
	}

	public long getLong() {
		if (varInt.length == 1) {
			return Util.getLong(new byte[] { 0, 0, 0, 0, 0, 0, 0, varInt[0] });
		} else if (varInt.length == 3) {
			return Util.getLong(new byte[] { 0, 0, 0, 0, 0, 0, varInt[1],
					varInt[2] });
		} else if (varInt.length == 5) {
			return Util.getLong(new byte[] { 0, 0, 0, 0, varInt[1], varInt[2],
					varInt[3], varInt[4] });
		} else if (varInt.length == 9) {
			return Util.getLong(new byte[] { varInt[1], varInt[2], varInt[3],
					varInt[4], varInt[5], varInt[6], varInt[7], varInt[8] });
		} else {
			throw new IllegalStateException("Byte[] has the wrong length.");
		}
	}
}
