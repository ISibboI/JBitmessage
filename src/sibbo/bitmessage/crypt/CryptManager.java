package sibbo.bitmessage.crypt;

import java.math.BigInteger;
import java.util.logging.Logger;

import sibbo.bitmessage.Options;
import sibbo.bitmessage.network.protocol.Util;

public class CryptManager {
	private static final Logger LOG = Logger.getLogger(CryptManager.class
			.getName());

	private static final CryptManager instance = new CryptManager();

	public static CryptManager getInstance() {
		return instance;
	}

	public static boolean checkSignature(byte[] data, byte[] signature) {
		// TODO Auto-generated method stub
		throw new RuntimeException("Not yet implemented");
	}

	private CryptManager() {
	}

	public void init() {

	}

	/**
	 * Tries to decrypt the given data using all known private keys.
	 * 
	 * @param encrypted
	 * @return
	 */
	public KeyDataPair tryDecryption(byte[] encrypted) {
		return null;
	}

	/**
	 * Checks if the proof of work done for the given data is sufficient.
	 * 
	 * @param data The data.
	 * @param nonce The POW nonce.
	 * @return True if the pow is sufficient.
	 */
	public static boolean checkPOW(byte[] data, byte[] nonce) {
		byte[] initialHash = Digest.sha512(data);
		byte[] hash = Digest.sha512(Digest.sha512(nonce, initialHash));
		long value = Util.getLong(hash);
		long target = getPOWTarget(data.length);

		return value >= 0 && target >= value;
	}

	/**
	 * Returns the POW target for a message with the given length.
	 * 
	 * @param length The message length.
	 * @return The POW target for a message with the given length.
	 */
	public static long getPOWTarget(int length) {
		// // Testing:
		// return (long) Math.pow(2, 60);

		BigInteger powTarget = BigInteger.valueOf(2);
		powTarget = powTarget.pow(64);
		powTarget = powTarget.divide(BigInteger.valueOf((length
				+ Options.getInstance().getPOWPayloadLengthExtraBytes() + 8)
				* Options.getInstance().getPOWAverageNonceTrialsPerByte()));

		// Note that we are dividing through at least 8, so that the value is
		// smaller than 2^61 and fits perfectly into a long.
		return powTarget.longValue();
	}

	/**
	 * Does the POW for the given payload.<br />
	 * <b>WARNING: Takes a long time!!!</b>
	 * 
	 * @param payload
	 * @return
	 */
	public static byte[] doPOW(byte[] payload) {
		POWCalculator pow = new POWCalculator(getPOWTarget(payload.length),
				Digest.sha512(payload), Options.getInstance()
						.getPOWSystemLoad());
		return pow.execute();
	}
}