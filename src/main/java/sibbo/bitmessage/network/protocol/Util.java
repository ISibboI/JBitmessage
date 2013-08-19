package sibbo.bitmessage.network.protocol;

import java.math.BigInteger;
import java.util.logging.Logger;

import org.bouncycastle.jce.provider.JCEECPublicKey;

import sibbo.bitmessage.crypt.CryptManager;

/**
 * Provides some methods that are useful in multiple places.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 * 
 */
public final class Util {
	private static final Logger LOG = Logger.getLogger(Util.class.getName());

	/** Utility class */
	private Util() {
	}

	/**
	 * Returns a byte array containing the bytes of the given integer in big
	 * endian order.
	 * 
	 * @param i
	 *            The integer to convert.
	 * @return A byte array containing the 4 bytes of the given integer in big
	 *         endian order.
	 */
	public static byte[] getBytes(int i) {
		return new byte[] { (byte) (i >> 24), (byte) (i >> 16 & 0xFF), (byte) (i >> 8 & 0xFF), (byte) (i & 0xFF) };
	}

	/**
	 * Returns a byte array containing the bytes of the given short in big
	 * endian order.
	 * 
	 * @param i
	 *            The short to convert.
	 * @return A byte array containing the 2 bytes of the given short in big
	 *         endian order.
	 */
	public static byte[] getBytes(short i) {
		return new byte[] { (byte) (i >> 8), (byte) (i & 0xFF) };
	}

	/**
	 * Creates an integer created from the given bytes.
	 * 
	 * @param b
	 *            The byte data in big endian order.
	 * @return An integer created from the given bytes.
	 */
	public static int getInt(byte[] b) {
		int i = 0;

		i |= (b[0] & 0xFF) << 24;
		i |= (b[1] & 0xFF) << 16;
		i |= (b[2] & 0xFF) << 8;
		i |= (b[3] & 0xFF);

		return i;
	}

	/**
	 * Returns a byte array containing the bytes of the given long in big endian
	 * order.
	 * 
	 * @param l
	 *            The long to convert.
	 * @return A byte array containing the 4 bytes of the given long in big
	 *         endian order.
	 */
	public static byte[] getBytes(long l) {
		return new byte[] { (byte) (l >> 56), (byte) (l >> 48), (byte) (l >> 40), (byte) (l >> 32), (byte) (l >> 24),
				(byte) (l >> 16 & 0xFF), (byte) (l >> 8 & 0xFF), (byte) (l & 0xFF) };
	}

	/**
	 * Returns a long created from the given bytes.
	 * 
	 * @param b
	 *            The byte data in big endian order.
	 * @return A long created from the given bytes.
	 */
	public static long getLong(byte[] b) {
		long l = 0;

		l |= (b[0] & 0xFFL) << 56;
		l |= (b[1] & 0xFFL) << 48;
		l |= (b[2] & 0xFFL) << 40;
		l |= (b[3] & 0xFFL) << 32;
		l |= (b[4] & 0xFFL) << 24;
		l |= (b[5] & 0xFFL) << 16;
		l |= (b[6] & 0xFFL) << 8;
		l |= (b[7] & 0xFFL);

		return l;
	}

	/**
	 * Returns a short created from the given bytes.
	 * 
	 * @param b
	 *            The byte data in big endian order.
	 * @param offset
	 *            The first byte of the number.
	 * @return A short created from the given bytes.
	 */
	public static short getShort(byte[] b, int offset) {
		short s = 0;

		s |= (b[offset] & 0xFF) << 8;
		s |= (b[offset + 1] & 0xFF);

		return s;
	}

	/**
	 * Returns a short created from the given bytes.
	 * 
	 * @param b
	 *            The byte data in big endian order.
	 * @return A short created from the given bytes.
	 */
	public static short getShort(byte[] b) {
		return getShort(b, 0);
	}

	/**
	 * Returns a positive BigInteger from the given bytes. (Big endian)
	 * 
	 * @param data
	 *            The bytes.
	 * @param offset
	 *            The first byte.
	 * @param length
	 *            The amount of bytes to process.
	 * @return A BigInteger from the given bytes.
	 */
	public static BigInteger getUnsignedBigInteger(byte[] data, int offset, int length) {
		if (length == 0) {
			return BigInteger.ZERO;
		}

		byte[] value = new byte[length + 1];
		System.arraycopy(data, offset, value, 1, length);

		return new BigInteger(value);
	}

	/**
	 * Returns an unsigned byte[] representation of the given big integer.
	 * 
	 * @param number
	 *            The BigInteger. Must be >= 0.
	 * @param length
	 *            The maximum length.
	 * @return The last <code>length</code> bytes of the given big integer,
	 *         filled with zeros if necessary.
	 */
	public static byte[] getUnsignedBytes(BigInteger number, int length) {
		byte[] value = number.toByteArray();

		if (value.length > length + 1) {
			throw new IllegalArgumentException(
					"The given BigInteger does not fit into a byte array with the given length: " + value.length
							+ " > " + length);
		}

		byte[] result = new byte[length];

		int i = value.length == length + 1 ? 1 : 0;
		for (; i < value.length; i++) {
			result[i + length - value.length] = value[i];
		}

		return result;
	}

	public static byte[] getBytes(JCEECPublicKey publicSigningKey) {
		byte[] x = getUnsignedBytes(publicSigningKey.getQ().getX().toBigInteger(), 32);
		byte[] y = getUnsignedBytes(publicSigningKey.getQ().getY().toBigInteger(), 32);
		byte[] result = new byte[64];

		System.arraycopy(x, 0, result, 0, 32);
		System.arraycopy(y, 0, result, 32, 32);

		return result;
	}

	public static JCEECPublicKey getPublicKey(byte[] b) {
		if (b.length != 64) {
			throw new IllegalArgumentException("Need exactly 64 bytes, but have " + b.length + ".");
		}

		BigInteger x = getUnsignedBigInteger(b, 0, 32);
		BigInteger y = getUnsignedBigInteger(b, 32, 32);

		return CryptManager.getInstance().createPublicEncryptionKey(x, y);
	}
}