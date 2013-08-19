package sibbo.bitmessage.network.protocol;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Objects;

import org.bouncycastle.jce.provider.JCEECPublicKey;

import sibbo.bitmessage.crypt.CryptManager;

/**
 * Represents an encrypted message in the bitmessage encryption format.
 * 
 * @author Sebastian Schmidt
 */
public class EncryptedMessage extends Message {
	/** The initialization vector for AES. */
	private byte[] iv;

	/** The public key to generate the shared secret. */
	private JCEECPublicKey publicKey;

	/** The encrypted data. */
	private byte[] encrypted;

	/** The HmacSHA256 value. */
	private byte[] mac;

	/**
	 * Creates a new Encrypted Message with the given parameters.
	 * 
	 * @param iv
	 *            The AES initialization vector. Must have a length of 16.
	 * @param publicKey
	 *            The public key used to generate the shared secret.
	 * @param encrypted
	 *            The encrypted message. Must have a length of n * 16.
	 * @param mac
	 *            The message authentication code. Must have a length of 32.
	 */
	public EncryptedMessage(byte[] iv, JCEECPublicKey publicKey, byte[] encrypted, byte[] mac) {
		Objects.requireNonNull(iv, "'iv' must not be null.");
		Objects.requireNonNull(publicKey, "'publicKey' must not be null.");
		Objects.requireNonNull(encrypted, "'encrypted' must not be null.");
		Objects.requireNonNull(mac, "'mac' must not be null.");

		if (iv.length != 16) {
			throw new IllegalArgumentException("'iv' must have a length of 16.");
		}

		if (encrypted.length % 16 != 0) {
			throw new IllegalArgumentException("'encrypted' must have a length of n * 16.");
		}

		if (mac.length != 32) {
			throw new IllegalArgumentException("'mac' must have a length of 32.");
		}

		this.iv = iv;
		this.publicKey = publicKey;
		this.encrypted = encrypted;
		this.mac = mac;
	}

	/**
	 * {@link Message#Message(InputBuffer)}
	 */
	public EncryptedMessage(InputBuffer b) throws IOException, ParsingException {
		super(b);
	}

	@Override
	protected void read(InputBuffer b) throws IOException, ParsingException {
		iv = b.get(0, 16);

		int curve = Util.getShort(b.get(16, 2));

		if (curve != 714) {
			throw new ParsingException("Unknown curve: " + 714);
		}

		int xLength = Util.getShort(b.get(18, 2));

		if (xLength > 32 || xLength < 0) {
			throw new ParsingException("xLength must be between 0 and 32: " + xLength);
		}

		BigInteger x = Util.getUnsignedBigInteger(b.get(20, xLength), 0, xLength);
		b = b.getSubBuffer(xLength + 20);

		int yLength = Util.getShort(b.get(0, 2));

		if (yLength > 32 || yLength < 0) {
			throw new ParsingException("yLength must be between 0 and 32: " + yLength);
		}

		BigInteger y = Util.getUnsignedBigInteger(b.get(2, yLength), 0, yLength);
		b = b.getSubBuffer(2 + yLength);

		publicKey = CryptManager.getInstance().createPublicEncryptionKey(x, y);

		encrypted = b.get(0, b.length() - 32);
		mac = b.get(b.length() - 32, 32);
	}

	@Override
	public byte[] getBytes() {
		byte[] result = new byte[16 + 70 + encrypted.length + mac.length];

		System.arraycopy(iv, 0, result, 0, 16);
		System.arraycopy(Util.getBytes((short) 714), 0, result, 16, 2);
		System.arraycopy(Util.getBytes((short) 32), 0, result, 18, 2);
		System.arraycopy(Util.getUnsignedBytes(publicKey.getQ().getX().toBigInteger(), 32), 0, result, 20, 32);
		System.arraycopy(Util.getBytes((short) 32), 0, result, 52, 2);
		System.arraycopy(Util.getUnsignedBytes(publicKey.getQ().getY().toBigInteger(), 32), 0, result, 54, 32);
		System.arraycopy(encrypted, 0, result, 86, encrypted.length);
		System.arraycopy(mac, 0, result, result.length - 32, 32);

		return result;
	}

	public byte[] getIV() {
		return iv;
	}

	public JCEECPublicKey getPublicKey() {
		return publicKey;
	}

	public byte[] getEncrypted() {
		return encrypted;
	}

	public byte[] getMac() {
		return mac;
	}
}