package sibbo.bitmessage.protocol;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

import sibbo.bitmessage.crypt.Digest;

/**
 * Wraps any kind of message that can be sent over the network.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 * 
 */
public class BaseMessage extends Message {
	private static final Logger LOG = Logger.getLogger(BaseMessage.class
			.getName());

	/** See protocol specification. */
	private byte[] magic;

	/** A NULL-padded ASCII string with a length of 12. */
	private byte[] command;

	/** The length of the payload. */
	private byte[] length;

	/** The first 4 bytes of the sha512 checksum of the payload. */
	private byte[] checksum;

	/** The payload */
	private byte[] payload;

	/**
	 * Constructs a new Message with the given parameters.
	 * 
	 * @param magic See protocol specification.
	 * @param command A NULL-padded ASCII string with a length of 12.
	 * @param payload The payload.
	 */
	public BaseMessage(byte[] magic, String command, Message payload) {
		Objects.requireNonNull(magic, "magic must not be null.");
		Objects.requireNonNull(command, "command must not be null.");
		Objects.requireNonNull(payload, "payload must not be null.");

		if (magic.length != 4) {
			throw new IllegalArgumentException("magic must have a length of 4");
		}

		if (command.length() > 12) {
			throw new IllegalArgumentException(
					"command must not be longer than 12");
		}

		try {
			this.command = new byte[12];
			byte[] ascii = command.getBytes("ASCII");

			for (int i = 0; i < ascii.length; i++) {
				this.command[i] = ascii[i];
			}
		} catch (UnsupportedEncodingException e) {
			LOG.log(Level.SEVERE, "ASCII not supported!", e);
			System.exit(1);
		}

		this.payload = payload.getBytes();
		this.length = Util.getBytes(this.payload.length);
		this.magic = magic;
		this.checksum = Digest.sha512(this.payload, 4);

	}

	/**
	 * {@link Message#NetworkMessage(InputStream)}
	 */
	public BaseMessage(InputStream in) throws IOException, ParsingException {
		super(in);
	}

	public byte[] getMagic() {
		return magic;
	}

	public String getCommand() {
		try {
			return new String(command, "ASCII");
		} catch (UnsupportedEncodingException e) {
			LOG.log(Level.SEVERE, "ASCII not supported!", e);
			System.exit(1);
			return null;
		}
	}

	public int getLength() {
		return Util.getInt(length);
	}

	public byte[] getChecksum() {
		return checksum;
	}

	public byte[] getPayload() {
		return payload;
	}

	@Override
	public byte[] getBytes() {
		ByteArrayOutputStream b = new ByteArrayOutputStream();

		try {
			b.write(magic);
			b.write(command);
			b.write(length);
			b.write(checksum);
			b.write(payload);
		} catch (IOException e) {
			LOG.log(Level.SEVERE, "Could not write bytes!", e);
		}

		return b.toByteArray();
	}

	@Override
	protected void read(InputStream in) throws IOException, ParsingException {
		magic = new byte[4];
		readComplete(in, magic);

		command = new byte[12];
		readComplete(in, command);

		length = new byte[4];
		readComplete(in, length);

		checksum = new byte[4];
		readComplete(in, checksum);

		int l = getLength();

		if (l < 0) {
			throw new ParsingException("The length of the payload is < 0");
		}

		if (l > 10 * 1024 * 1024) {
			throw new ParsingException("The payload is to long: " + l
					+ " bytes");
		}

		payload = new byte[l];
		readComplete(in, payload);

		if (!Arrays.equals(checksum, Digest.sha512(payload, 4))) {
			throw new ParsingException("Wrong digest for payload!");
		}
	}
}