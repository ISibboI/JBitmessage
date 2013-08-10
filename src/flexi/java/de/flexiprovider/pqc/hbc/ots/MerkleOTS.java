/*
 * Created on Sep 15, 2005
 *
 * TODO To change the template for this generated file go to
 * Window - Preferences - Java - Code Style - Code Templates
 */
package de.flexiprovider.pqc.hbc.ots;

import de.flexiprovider.api.MessageDigest;
import de.flexiprovider.common.math.IntegerFunctions;
import de.flexiprovider.pqc.hbc.PRNG;

/**
 * This class implements key pair generation and signature generation of the
 * Merkle one-time signature scheme, described in R. Merkle, "A certified
 * digital signature", LNCS 1462, pages 218&#8211;238, 1989. The class is used
 * by the CMSS classes.
 * 
 * @author Elena Klintsevich
 */
public class MerkleOTS implements OTS {

	// the hash function used by the OTS
	private MessageDigest md;

	// the RNG used for key pair generation
	private PRNG rng;

	// the lengths of the message digest and private key
	private int mdSize, keySize;

	// the private key bytes
	private byte[][] privKeyBytes;

	// the verification key bytes
	private byte[] pubKeyBytes;

	/**
	 * Initialize the OTS.
	 * 
	 * @param md
	 *                the hash function for the OTS
	 * @param rng
	 *                the name of the PRNG used for key pair generation
	 */
	public void init(MessageDigest md, PRNG rng) {
		this.md = md;
		this.rng = rng;

		// compute key size for private and public key and also the help array
		// s, log s, keySize
		mdSize = md.getDigestLength();

		// compute the key size
		int logs = IntegerFunctions.ceilLog256((mdSize << 3) + 1);
		keySize = (mdSize + logs) << 3;
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

		pubKeyBytes = new byte[keySize * mdSize];
		byte[] help = new byte[mdSize];

		for (int i = 0; i < keySize; i++) {
			help = md.digest(privKeyBytes[i]);

			System.arraycopy(help, 0, pubKeyBytes, i * mdSize, mdSize);
		}
	}

	/**
	 * @return The verification OTS key as one byte array
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

		int counter0 = 0;
		// create hash of message m
		byte[] hash = md.digest(mBytes);
		byte[] help;
		int cntr = 0;
		for (int i = 0; i < hash.length; i++) {
			if ((hash[i] & 1) == 1) {
				System.arraycopy(privKeyBytes[8 * i], 0, sigBytes, cntr, mdSize);
			} else {
				help = md.digest(privKeyBytes[8 * i]);
				System.arraycopy(help, 0, sigBytes, cntr, mdSize);
				counter0++;
			}

			cntr += mdSize;

			if ((hash[i] & 2) == 2) {
				System.arraycopy(privKeyBytes[8 * i + 1], 0, sigBytes, cntr, mdSize);
			} else {
				help = md.digest(privKeyBytes[8 * i + 1]);
				System.arraycopy(help, 0, sigBytes, cntr, mdSize);
				counter0++;
			}

			cntr += mdSize;

			if ((hash[i] & 4) == 4) {
				System.arraycopy(privKeyBytes[8 * i + 2], 0, sigBytes, cntr, mdSize);
			} else {
				help = md.digest(privKeyBytes[8 * i + 2]);
				System.arraycopy(help, 0, sigBytes, cntr, mdSize);
				counter0++;
			}

			cntr += mdSize;

			if ((hash[i] & 8) == 8) {
				System.arraycopy(privKeyBytes[8 * i + 3], 0, sigBytes, cntr, mdSize);
			} else {
				help = md.digest(privKeyBytes[8 * i + 3]);
				System.arraycopy(help, 0, sigBytes, cntr, mdSize);
				counter0++;
			}

			cntr += mdSize;

			if ((hash[i] & 16) == 16) {
				System.arraycopy(privKeyBytes[8 * i + 4], 0, sigBytes, cntr, mdSize);
			} else {
				help = md.digest(privKeyBytes[8 * i + 4]);
				System.arraycopy(help, 0, sigBytes, cntr, mdSize);
				counter0++;
			}

			cntr += mdSize;

			if ((hash[i] & 32) == 32) {
				System.arraycopy(privKeyBytes[8 * i + 5], 0, sigBytes, cntr, mdSize);
			} else {
				help = md.digest(privKeyBytes[8 * i + 5]);
				System.arraycopy(help, 0, sigBytes, cntr, mdSize);
				counter0++;
			}

			cntr += mdSize;

			if ((hash[i] & 64) == 64) {
				System.arraycopy(privKeyBytes[8 * i + 6], 0, sigBytes, cntr, mdSize);
			} else {
				help = md.digest(privKeyBytes[8 * i + 6]);
				System.arraycopy(help, 0, sigBytes, cntr, mdSize);
				counter0++;
			}

			cntr += mdSize;

			if ((hash[i] & 128) == 128) {
				System.arraycopy(privKeyBytes[8 * i + 7], 0, sigBytes, cntr, mdSize);
			} else {
				help = md.digest(privKeyBytes[8 * i + 7]);
				System.arraycopy(help, 0, sigBytes, cntr, mdSize);
				counter0++;
			}

			cntr += mdSize;

		} // end for

		int t = mdSize << 3;

		while (counter0 != 0) {
			if ((counter0 & 1) == 1) {
				System.arraycopy(privKeyBytes[t], 0, sigBytes, cntr, mdSize);
			} else {
				help = md.digest(privKeyBytes[t]);
				System.arraycopy(help, 0, sigBytes, cntr, mdSize);
			}

			cntr += mdSize;
			counter0 >>>= 1;
			t++;
		}

		while (t < keySize) {
			help = md.digest(privKeyBytes[t]);
			System.arraycopy(help, 0, sigBytes, cntr, mdSize);
			cntr += mdSize;
			t++;
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
		if ((sigBytes.length % mdSize) != 0) {
			return null;
		}
		byte[] pubKeyBytes = new byte[sigBytes.length];

		int cntr0 = 0;

		// create hash of message m
		byte[] hash = md.digest(mBytes);

		byte[] help = new byte[mdSize];

		int cntr1 = 0;
		for (int i = 0; i < hash.length; i++) {
			if ((hash[i] & 1) == 1) {
				System.arraycopy(sigBytes, cntr1, help, 0, mdSize);
				md.update(help);
				help = md.digest();
				System.arraycopy(help, 0, pubKeyBytes, cntr1, mdSize);
			} else {
				System.arraycopy(sigBytes, cntr1, pubKeyBytes, cntr1, mdSize);
				cntr0++;
			}

			cntr1 += mdSize;

			if ((hash[i] & 2) == 2) {
				System.arraycopy(sigBytes, cntr1, help, 0, mdSize);
				md.update(help);
				help = md.digest();
				System.arraycopy(help, 0, pubKeyBytes, cntr1, mdSize);
			} else {
				System.arraycopy(sigBytes, cntr1, pubKeyBytes, cntr1, mdSize);
				cntr0++;
			}

			cntr1 += mdSize;

			if ((hash[i] & 4) == 4) {
				System.arraycopy(sigBytes, cntr1, help, 0, mdSize);
				md.update(help);
				help = md.digest();
				System.arraycopy(help, 0, pubKeyBytes, cntr1, mdSize);
			} else {
				System.arraycopy(sigBytes, cntr1, pubKeyBytes, cntr1, mdSize);
				cntr0++;
			}

			cntr1 += mdSize;

			if ((hash[i] & 8) == 8) {
				System.arraycopy(sigBytes, cntr1, help, 0, mdSize);
				md.update(help);
				help = md.digest();
				System.arraycopy(help, 0, pubKeyBytes, cntr1, mdSize);
			} else {
				System.arraycopy(sigBytes, cntr1, pubKeyBytes, cntr1, mdSize);
				cntr0++;
			}

			cntr1 += mdSize;

			if ((hash[i] & 16) == 16) {
				System.arraycopy(sigBytes, cntr1, help, 0, mdSize);
				md.update(help);
				help = md.digest();
				System.arraycopy(help, 0, pubKeyBytes, cntr1, mdSize);
			} else {
				System.arraycopy(sigBytes, cntr1, pubKeyBytes, cntr1, mdSize);
				cntr0++;
			}

			cntr1 += mdSize;

			if ((hash[i] & 32) == 32) {
				System.arraycopy(sigBytes, cntr1, help, 0, mdSize);
				md.update(help);
				help = md.digest();
				System.arraycopy(help, 0, pubKeyBytes, cntr1, mdSize);
			} else {
				System.arraycopy(sigBytes, cntr1, pubKeyBytes, cntr1, mdSize);
				cntr0++;
			}

			cntr1 += mdSize;

			if ((hash[i] & 64) == 64) {
				System.arraycopy(sigBytes, cntr1, help, 0, mdSize);
				md.update(help);
				help = md.digest();
				System.arraycopy(help, 0, pubKeyBytes, cntr1, mdSize);
			} else {
				System.arraycopy(sigBytes, cntr1, pubKeyBytes, cntr1, mdSize);
				cntr0++;
			}

			cntr1 += mdSize;

			if ((hash[i] & 128) == 128) {
				System.arraycopy(sigBytes, cntr1, help, 0, mdSize);
				md.update(help);
				help = md.digest();
				System.arraycopy(help, 0, pubKeyBytes, cntr1, mdSize);
			} else {
				System.arraycopy(sigBytes, cntr1, pubKeyBytes, cntr1, mdSize);
				cntr0++;
			}

			cntr1 += mdSize;
		}

		while (cntr0 != 0) {
			if ((cntr0 & 1) == 1) {
				System.arraycopy(sigBytes, cntr1, help, 0, mdSize);
				md.update(help);
				help = md.digest();
				System.arraycopy(help, 0, pubKeyBytes, cntr1, mdSize);
			} else {
				System.arraycopy(sigBytes, cntr1, pubKeyBytes, cntr1, mdSize);
			}

			cntr1 += mdSize;
			cntr0 >>>= 1;
		}

		while (cntr1 < sigBytes.length) {
			System.arraycopy(sigBytes, cntr1, pubKeyBytes, cntr1, mdSize);
			cntr1 += mdSize;
		}

		return pubKeyBytes;
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
