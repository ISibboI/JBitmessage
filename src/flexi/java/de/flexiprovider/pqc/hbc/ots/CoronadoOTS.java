package de.flexiprovider.pqc.hbc.ots;

import de.flexiprovider.api.MessageDigest;
import de.flexiprovider.common.math.IntegerFunctions;
import de.flexiprovider.common.util.ByteUtils;
import de.flexiprovider.pqc.hbc.PRNG;

/**
 * This class implements key pair generation and signature generation of the
 * Coronado one-time signature scheme (OTSS), described in the Cryptology ePrint
 * archive article "On the security and the effiency of the Merkle signature
 * scheme". The class is used by the CMSS classes.
 * 
 * @author Elena Klintsevich
 */
public class CoronadoOTS implements OTS {

	// the hash function used by the OTS
	private MessageDigest md;

	// the RNG used for key pair generation
	private PRNG rng;

	// the lengths of the message digest output and private key
	private int mdSize, keySize;

	// the private key
	private byte[][] privKeyBytes;

	// the verification key
	private byte[] pubKeyBytes;

	/**
	 * Initialize the OTS.
	 * 
	 * @param md
	 *                the hash function for the OTS
	 * @param rng
	 *                the RNG used for key pair generation
	 */
	public void init(MessageDigest md, PRNG rng) {
		this.md = md;
		this.rng = rng;

		// compute key size for private and public key and also the help array
		// s, log s, keySize
		mdSize = md.getDigestLength();

		// compute the key size
		int logs = IntegerFunctions.ceilLog256((mdSize << 2) + 1);
		keySize = (mdSize + 3 * logs) << 2;
	}

	/**
	 * Generate an OTS key pair using the given seed and the message digest and
	 * PRNG specified via {@link #init(MessageDigest, PRNG)}.
	 * 
	 * @param seed
	 *                the seed for the PRGN
	 */
	public void generateKeyPair(byte[] seed) {
		// generate random bytes and assign them to the private key
		privKeyBytes = new byte[keySize][mdSize];
		for (int i = 0; i < keySize; i++) {
			privKeyBytes[i] = rng.nextSeed(seed);
		}

		byte[] tmpPubKey = new byte[keySize * mdSize];
		byte[] help = new byte[mdSize];

		// hash the private key and assign it to the public key
		for (int i = 0; i < keySize; i++) {
			help = md.digest(privKeyBytes[i]);
			help = md.digest(help);
			help = md.digest(help);
			System.arraycopy(help, 0, tmpPubKey, mdSize * i, mdSize);
		}

		pubKeyBytes = md.digest(tmpPubKey);
	}

	/**
	 * @return the verification key generated via {@link #generateKeyPair(byte[])}
	 */
	public byte[] getVerificationKey() {
		return pubKeyBytes;
	}

	/**
	 * @return the length of the one-time signature
	 */
	public int getSignatureLength() {
		return keySize * mdSize;
	}

	/**
	 * Generate a one-time signature of the given message using the private key
	 * generated via {@link #generateKeyPair(byte[])}.
	 * 
	 * @param mBytes
	 *                the message
	 * @return the one-time signature of the message
	 */
	public byte[] sign(byte[] mBytes) {
		byte[] sigBytes = new byte[keySize * mdSize];
		// number of zeros, every integer can be coded
		byte[] zot;
		// test byte
		byte test = 0;
		int counter = 0;

		// create hash of message m
		byte[] hash = md.digest(mBytes);
		zot = countBits(hash);

		// merge the arrays of the hash and the countedBits
		byte[] dest = ByteUtils.concatenate(hash, zot);

		// create signature
		for (int i = 0; i < dest.length; i++) {
			for (int j = 0; j < 4; j++) {
				test = (byte) ((dest[i] & 0xff) >>> 6);
				byte[] hlp = new byte[mdSize];

				System.arraycopy(privKeyBytes[counter], 0, hlp, 0, mdSize);

				while (test > 0) {
					hlp = md.digest(hlp);
					test--;
				}
				System.arraycopy(hlp, 0, sigBytes, counter * mdSize, mdSize);
				dest[i] = (byte) (dest[i] << 2);
				counter++;
			}
		}

		return sigBytes;
	}

	/**
	 * Compute the OTS verification key from the one-time signature of a message. This
	 * is *NOT* a complete OTS signature verification, but it suffices for usage
	 * with CMSS.
	 * 
	 * @param mBytes
	 *                the message
	 * @param sigBytes
	 *                the one-time signature
	 * @return the OTS verification key
	 */
	public byte[] computeVerificationKey(byte[] mBytes, byte[] sigBytes) {
		// create hash of message m
		byte[] hash = md.digest(mBytes);
		byte[] zot = countBits(hash);

		// merge the arrays of the hash and the countedBits
		byte[] dest = ByteUtils.concatenate(hash, zot);

		byte[] tmpPubKey = new byte[(mdSize * dest.length) << 2];

		int counter = 0;

		// verify signature
		for (int i = 0; i < dest.length; i++) {
			for (int j = 0; j < 4; j++) {
				byte test = (byte) ((dest[i] & 0xff) >>> 6);
				byte[] hlp = new byte[mdSize];
				System.arraycopy(sigBytes, counter * mdSize, hlp, 0, mdSize);
				while (test < 3) {
					hlp = md.digest(hlp);
					test++;
				}
				System.arraycopy(hlp, 0, tmpPubKey, counter * mdSize, mdSize);
				dest[i] = (byte) (dest[i] << 2);
				counter++;
			}
		}

		return md.digest(tmpPubKey);
	}

	/**
	 * This method interprets every two bits of the input array as a decimal
	 * numbers and counts the number of zeros, ones, and twos among these
	 * numbers. It returns a byte array containing the concatenation of the
	 * three counters.
	 * 
	 * @param inputArray
	 *                the input array
	 * 
	 * @return a byte array containing the concatenation of the three counters
	 */
	private byte[] countBits(byte[] inputArray) {
		int t = inputArray.length;
		byte[] byteArray = new byte[t];
		System.arraycopy(inputArray, 0, byteArray, 0, t);
		t = IntegerFunctions.ceilLog256((t << 2) + 1);
		byte[] counters = new byte[3 * t];
		int counter0 = 0, counter1 = 0, counter2 = 0;
		byte test = 0;
		// count zeros, ones and twos in a byte array
		for (int i = 0; i < byteArray.length; i++) {
			for (int j = 0; j < 4; j++) {
				test = (byte) (byteArray[i] & 3);
				switch (test) {
				case 0:
					counter0++;
					break;
				case 1:
					counter1++;
					break;
				case 2:
					counter2++;
					break;
				default:
				}

				byteArray[i] >>>= 2;
			}
		}

		int a;
		// write integer counter in the array countedBits
		for (int i = 1; i <= t; i++) {
			a = t - i;
			counters[a] = (byte) (counter0 & 0xff);
			counter0 >>>= 8;
			a += t; // a = 2t - i
			counters[a] = (byte) (counter1 & 0xff);
			counter1 >>>= 8;
			a += t; // a = 3t - i
			counters[a] = (byte) (counter2 & 0xff);
			counter2 >>>= 8;
		}

		return counters;
	}

	////for compatibility with interface OTS
	public boolean canComputeVerificationKeyFromSignature() {
		return true;
	}

	public void generateSignatureKey(byte[] seed) {
	}

	public void generateVerificationKey() {
	}

	public int getVerificationKeyLength() {
		return 0;
	}

	public boolean verify(byte[] mBytes, byte[] sBytes, byte[] pBytes) {
		return false;
	}

}
