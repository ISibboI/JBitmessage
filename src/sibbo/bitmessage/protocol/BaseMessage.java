package sibbo.bitmessage.protocol;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

import sibbo.bitmessage.crypt.Digest;

/**
 * Wraps any kind of message that can be sent over the network.
 * 
 * @author Sebastian Schmidt
 * @version 1.0System.exit(1);
 * 
 */
public class BaseMessage {
	private static final Logger LOG = Logger.getLogger(BaseMessage.class
			.getName());

	/** Stores the types that are used to parse the commands */
	private static final HashMap<String, Class<? extends P2PMessage>> COMMANDS = new HashMap<>();

	static {
		COMMANDS.put(VersionMessage.COMMAND, VersionMessage.class);
		COMMANDS.put(VerAckMessage.COMMAND, VerAckMessage.class);
		COMMANDS.put(AddrMessage.COMMAND, AddrMessage.class);
		COMMANDS.put(InvMessage.COMMAND, InvMessage.class);
		COMMANDS.put(GetdataMessage.COMMAND, GetdataMessage.class);
		// TODO Fill COMMANDS
	}

	/** Identifies the bitmessage protocol. */
	private byte[] magic = new byte[] { (byte) 0xE9, (byte) 0xBE, (byte) 0xB4,
			(byte) 0xD9 };

	/** The command of the message. */
	private String command;

	/** The length of the payload. */
	private int length = -1;

	/** The first 4 bytes of the sha512 checksum of the payload. */
	private byte[] checksum = null;

	/** The payload */
	private P2PMessage payload;

	/**
	 * Constructs a new Message with the given parameters.
	 * 
	 * @param command A NULL-padded ASCII string with a length of 12.
	 * @param payload The payload.
	 */
	public BaseMessage(P2PMessage payload) {
		Objects.requireNonNull(payload, "payload must not be null.");

		this.payload = payload;
		this.command = payload.getCommand();
	}

	/**
	 * Creates a new base message, parsing the data from in. The message is
	 * limited to maxLength.
	 * 
	 * @param in The input stream to read from.
	 * @param maxLength The maximum amount of bytes to read from in.
	 */
	public BaseMessage(InputStream in, int maxLength) throws IOException,
			ParsingException {
		read(in, maxLength);
	}

	public byte[] getMagic() {
		return magic;
	}

	public String getCommand() {
		return command;
	}

	/**
	 * Returns the length of the payload. If the getBytes() method hasn't be
	 * used already, the return value is -1.
	 * 
	 * @return The length of the payload or -1 if getBytes() hasn't been used.
	 */
	public int getLength() {
		return length;
	}

	public byte[] getChecksum() {
		return checksum;
	}

	public P2PMessage getPayload() {
		return payload;
	}

	public byte[] getBytes() {
		ByteArrayOutputStream b = new ByteArrayOutputStream();

		try {
			b.write(magic);

			byte[] ascii = command.getBytes("ASCII");

			for (int i = 0; i < 12; i++) {
				if (i < ascii.length) {
					b.write(ascii[i]);
				} else {
					b.write(0);
				}
			}

			byte[] pbytes = payload.getBytes();
			length = pbytes.length;
			checksum = Digest.sha512(pbytes, 4);

			b.write(Util.getBytes(length));
			b.write(checksum);
			b.write(pbytes);
		} catch (UnsupportedEncodingException e) {
			LOG.log(Level.SEVERE, "ASCII not supported!", e);
			System.exit(1);
		} catch (IOException e) {
			LOG.log(Level.SEVERE, "Could not write bytes!", e);
			System.exit(1);
		}

		return b.toByteArray();
	}

	protected void read(InputStream in, int maxLength) throws IOException,
			ParsingException {
		InputBuffer buffer = new InputBuffer(in, 24, 24);

		if (!Arrays.equals(magic, buffer.get(0, 4))) {
			throw new ParsingException("Unknown magic bytes: "
					+ Arrays.toString(buffer.get(0, 4)));
		}

		byte[] ascii = buffer.get(4, 12);

		StringBuilder str = new StringBuilder();

		for (byte b : ascii) {
			if (b == 0) {
				break;
			}

			str.append(new String(new byte[] { b }, "ASCII"));
		}

		command = str.toString();

		length = Util.getInt(buffer.get(16, 4));

		checksum = buffer.get(20, 4);

		if (length < 0) {
			throw new ParsingException("The length of the payload is < 0");
		}

		if (length > maxLength) {
			throw new ParsingException("The payload is too long: " + length
					+ " bytes");
		}

		buffer = new InputBuffer(in, 128, length);
		byte[] payloadBytes = buffer.get(0, length);

		if (!Arrays.equals(checksum, Digest.sha512(payloadBytes, 4))) {
			throw new ParsingException("Wrong digest for payload!");
		}

		try {
			Class<? extends P2PMessage> cPayload = getPayloadType(command);

			if (cPayload == null) {
				throw new ParsingException("Unknown command: " + command);
			}

			Constructor<? extends P2PMessage> constructor = cPayload
					.getConstructor(InputBuffer.class);
			payload = constructor.newInstance(buffer);
		} catch (NoSuchMethodException e) {
			LOG.log(Level.SEVERE, "INTERNAL: The type bound to " + command
					+ " is missing a Constructor(InputStream)!", e);
			System.exit(1);
		} catch (InstantiationException e) {
			LOG.log(Level.SEVERE, "INTERNAL: The type bound to " + command
					+ " is abstract!", e);
			System.exit(1);
		} catch (IllegalAccessException e) {
			LOG.log(Level.SEVERE, "INTERNAL: The type bound to " + command
					+ " has an inaccessible Constructor(InputStream)!", e);
			System.exit(1);
		} catch (IllegalArgumentException e) {
			LOG.log(Level.SEVERE, "INTERNAL: The type bound to " + command
					+ " caused an error!", e);
			System.exit(1);
		} catch (InvocationTargetException e) {
			if (e.getCause() instanceof ParsingException) {
				throw (ParsingException) e.getCause();
			} else if (e.getCause() instanceof IOException) {
				throw (IOException) e.getCause();
			} else {
				LOG.log(Level.SEVERE, "INTERNAL: The type bound to " + command
						+ " caused an error!", e);
				System.exit(1);
			}
		}
	}

	public Class<? extends P2PMessage> getPayloadType(String command) {
		return COMMANDS.get(command);
	}
}