package de.flexiprovider.core.md.swifftx;

import de.flexiprovider.api.MessageDigest;

/**
 * 
 * This class implements the SWIFFTX224 hash function. It is designed by Yuriy
 * Arbitman, Gil Dogon, Vadim Lyubashevsky, Daniele Micciancio, Chris Peikert,
 * and Alon Rosen. It is a candidate for the SHA-3 competition. The
 * specification of the algorithm can be found at <a
 * href="http://www.eecs.harvard.edu/~alon/PAPERS/lattices/swifftx.pdf">. The
 * implementation is a direct translation from the reference C implementation.
 * 
 * @author Stephan Mönkehues
 * 
 */
public class SWIFFTX224 extends MessageDigest {

	/**
	 * The algorithm name.
	 */
	public static final String ALG_NAME = "SWIFFTX224";

	private int[] hashValue = new int[64];

	private int DIGEST_LENGTH = 28;

	/**
	 * Default constructor.
	 */
	public SWIFFTX224() {

	}

	/**
	 * Hashes the input.
	 * 
	 * @return the digested data
	 */
	public synchronized byte[] digest() {
		byte[] finalHash = new byte[DIGEST_LENGTH];
		int i = 0;
		for (i = 0; i < DIGEST_LENGTH; ++i) {
			finalHash[i] = (byte) hashValue[i];
		}

		return finalHash;
	}

	/**
	 * Resets this hash function for clearing any internal stages.
	 */
	public void reset() {

	}

	/**
	 * Returns the number of bytes of the output of the SWIFFTX224 hash
	 * function. This is 28.
	 * 
	 * @return the number of bytes of the output of the SWIFFTX224 hash function
	 *         which is 28.
	 */
	public int getDigestLength() {
		return DIGEST_LENGTH;
	}

	/**
	 * Update the digest using the specified byte.
	 * 
	 * @param input
	 *            the byte to use for the update
	 */
	public synchronized void update(byte input) {
	}

	/**
	 * Update the digest using the specified array of bytes, starting at the
	 * specified offset.
	 * 
	 * @param input
	 *            the array of bytes to use for the update
	 * @param offset
	 *            the offset to start from in the array of bytes
	 * @param len
	 *            the number of bytes to use, starting at <tt>offset</tt>
	 */
	public synchronized void update(byte[] input, int offset, int len) {
		hashValue = SWIFFTX.hash(224, input, input.length * 8);
	}

}