package sibbo.bitmessage.crypt;

import java.util.logging.Logger;

public class CryptManager {
	private static final Logger LOG = Logger.getLogger(CryptManager.class
			.getName());

	private static final CryptManager instance = new CryptManager();

	public static CryptManager getInstance() {
		return instance;
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

	public static void checkSignature(byte[] bytesWithoutSignature,
			byte[] signature) {
		// TODO Auto-generated method stub

	}
}