package sibbo.bitmessage.protocol;

import java.util.HashMap;

/**
 * A message encoding type.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 */
public enum MessageEncoding {
	IGNORE(0), TRIVIAL(1), SIMPLE(2);

	private static final HashMap<Long, MessageEncoding> MAP = new HashMap<>();

	/**
	 * Returns the message encoding that is associated with the given constant.
	 * 
	 * @param constant The constant.
	 * @return The message encoding that is associated with the given constant.
	 */
	public static MessageEncoding getEncoding(long constant) {
		return MAP.get(constant);
	}

	private long constant;

	private MessageEncoding(long constant) {
		this.constant = constant;
		put(constant, this);
	}

	private void put(long constant, MessageEncoding messageEncoding) {
		MAP.put(constant, messageEncoding);
	}

	/**
	 * Returns the constant that is associated with this message encoding.
	 * 
	 * @return The constant.
	 */
	public long getConstant() {
		return constant;
	}
}