package de.flexiprovider.pqc.hbc.ots;

import java.util.BitSet;

import de.flexiprovider.api.MessageDigest;
import de.flexiprovider.common.math.IntegerFunctions;
import de.flexiprovider.common.util.ByteUtils;
import de.flexiprovider.pqc.hbc.PRNG;

/**
 * Implementation of Winternitz OTS
 */

public class WinternitzOTS implements OTS {

	// the Winternitz parameter
	private int w;

	// the hash function used by the OTS
	private MessageDigest md;

	// the PRNG used for key pair generation
	private PRNG rng;

	// t, t1, t2 from the paper and the lengths of the digest
	private int t, t1, t2, mdSize;

	// the signature key X, the verification key Y
	private byte[][] X, Y;

	private final int wPowOfTow; // 2^w

	/**
	 * @param w
	 *            the Winternitz parameter
	 */
	public WinternitzOTS(int w) {
		this.w = w;
		this.wPowOfTow = 1 << w;
		if (w < 1) {
			System.err.println("w should >= 1");
		}
	}

	/**
	 * Initialize the OTS.
	 * 
	 * @param md
	 *            the hash function for the OTS
	 * @param rng
	 *            the name of the PRNG used for key pair generation
	 */
	public void init(MessageDigest md, PRNG rng) {
		this.md = md;
		this.rng = rng;
		mdSize = md.getDigestLength();

		double n = mdSize * 8.0;
		t1 = (int) Math.ceil(n / w);
		t2 = (int) Math.ceil((IntegerFunctions.floorLog(t1) + w + 1.0) / w);
		t = t1 + t2;
	}

	/**
	 * Generate an OTS key pair using the given seed and the message digest and
	 * PRNG specified via {@link #init(MessageDigest, PRNG)}.
	 * 
	 * @param seed
	 *            the seed for the PRGN
	 */
	public void generateKeyPair(byte[] seed) {
		generateSignatureKey(seed);
		generateVerificationKey();
	}

	/**
	 * Generate an OTS signature key the given seed and the message digest and
	 * PRNG specified via {@link #init(MessageDigest, PRNG)}.
	 * 
	 * @param seed
	 *            the seed for the PRGN
	 */
	public void generateSignatureKey(byte[] seed) {
		X = new byte[t][mdSize];
		for (int i = 0; i < t; i++) {
			X[i] = rng.nextSeed(seed);
		}
	}

	/**
	 * Generate an OTS verification key from the previously generated signature
	 * key given the message digest specified via
	 * {@link #init(MessageDigest, PRNG)}.
	 * 
	 */
	public void generateVerificationKey() {
		Y = new byte[t][mdSize];
		int repeat = wPowOfTow - 1;
		for (int i = 0; i < t; i++) {
			Y[i] = md.digest(X[i]);
			for (int j = 0; j < repeat - 1; j++) {
				Y[i] = md.digest(Y[i]);
			}
		}
	}

	/**
	 * @return the verification key generated via
	 *         {@link #generateKeyPair(byte[])}
	 */
	public byte[] getVerificationKey() {
		byte[] vkey = new byte[t * mdSize];
		for (int i = 0; i < t; i++) {
			System.arraycopy(Y[i], 0, vkey, i * mdSize, mdSize);
		}
		return vkey;
	}

	public int getVerificationKeyLength() {
		return t * mdSize;
	}

	public int getSignatureLength() {
		return t * mdSize;
	}

	/**
	 * Generate a one-time signature of the given message using the private key
	 * generated via {@link #generateKeyPair(byte[])}.
	 * 
	 * @param mBytes
	 *            the message
	 * @return the one-time signature of the message
	 */
	public byte[] sign(byte[] mBytes) {
		int[] b = generateB(mBytes);
		// generate signature
		byte[] sig = new byte[t * mdSize];
		for (int i = 0; i < t; i++) {
			for (int j = 0; j < b[i]; j++) {
				X[i] = md.digest(X[i]);
			}
			System.arraycopy(X[i], 0, sig, i * mdSize, mdSize);
		}
		return sig;
	}

	/**
	 * Verify a one-time signature of the given message using the verification
	 * key generated via {@link #generateKeyPair(byte[])}.
	 * 
	 * @param mBytes
	 *            the message
	 * @param sBytes
	 *            the signature
	 * @param pBytes
	 *            the verification key
	 * @return true if signature is valid and false otherwise
	 */
	public boolean verify(byte[] mBytes, byte[] sBytes, byte[] pBytes) {
		byte[] vKey = computeVerificationKey(mBytes, sBytes);
		return ByteUtils.equals(md.digest(vKey), md.digest(pBytes));
	}

	/**
	 * Compute the verification OTS key from the one-time signature of a
	 * message. This is *NOT* a complete OTS signature verification, but it
	 * suffices for usage with CMSS.
	 * 
	 * @param mBytes
	 *            the message
	 * @param sBytes
	 *            the one-time signature
	 * @return the verification OTS key
	 */
	public byte[] computeVerificationKey(byte[] mBytes, byte[] sBytes) {
		int[] b = generateB(mBytes);
		int a = wPowOfTow - 1;
		byte[] verify = new byte[t * mdSize], sig = new byte[mdSize];

		for (int i = 0; i < t; i++) {
			b[i] = a - b[i];
			System.arraycopy(sBytes, i * mdSize, sig, 0, mdSize);
			// apply f(sig) for 2^w-1-b[i] times
			for (int j = 0; j < b[i]; j++) {
				sig = md.digest(sig);
			}
			System.arraycopy(sig, 0, verify, i * mdSize, mdSize);
		}
		return verify;
	}

	public boolean canComputeVerificationKeyFromSignature() {
		return true;
	}

	/**
	 * split a binary string into 'num' blocks with length 'bitLength' and
	 * interpret each block as an integer.
	 * 
	 * @param sb
	 *            the binary string
	 * @param num
	 *            number of blocks
	 * @param step
	 *            the length of each block
	 * @return an array of integers
	 */
	private int[] parseBinaryString(BitSet s, int bitLength) {
		int block = bitLength % w, num = bitLength / w;

		int[] b = new int[block == 0 ? num : num + 1];

		int i = 0;
		if (block != 0) {
			for (int j = 0; j < block; j++) {
				if (s.get(block - 1 - j)) {
					b[0] += (1 << j);
				}
			}
			i++;
		}
		int offset = block;
		for (; offset < bitLength; offset += w, i++) { // parse b[i]
			for (int j = 0; j < w; j++) {
				if (s.get(offset + j)) {
					b[i] += (1 << (w - 1 - j));
				}
			}
		}
		return b;
	}

	/**
	 * generate the array b[] (see paper) from the message
	 * 
	 * @param mBytes
	 *            the message byte array
	 * @return the array b[]
	 */
	private int[] generateB(byte[] mBytes) {
		int[] b = new int[t];

		// binary representation of message digest
		byte[] d = md.digest(mBytes);
		BitSet bits = fromByteArray(d);

		int[] p = parseBinaryString(bits, d.length * 8);
		System.arraycopy(p, 0, b, 0, t1);

		int c = t1 << w;
		for (int i = 0; i < t1; i++) {
			c = c - b[i];
		}

		int length = t2 * w;
		bits = fromInteger(c, length); // binary representation of c
		p = parseBinaryString(bits, length);
		System.arraycopy(p, 0, b, t1, t2);

		return b;
	}

	/**
	 * Returns a bitSet containing the values in bytes. The bytes are big-endian
	 */
	private static BitSet fromByteArray(byte[] bytes) {
		int bytesLength = bytes.length;
		BitSet bits = new BitSet(bytesLength * 8);
		int byteOffset, i, j, b;
		for (i = 0; i < bytesLength; i++) {
			byteOffset = i << 3;
			b = 255 & bytes[i];
			for (j = 7; b != 0; j--) {
				if ((b & 1) != 0) {
					bits.set(byteOffset + j);
				}
				b = b >>> 1;
			}
		}
		return bits;
	}

	/** Generate Bit String from Integer */
	private static BitSet fromInteger(int n, int length) {
		BitSet bits = new BitSet();

		for (int i = length - 1; n != 0; i--) {
			if ((n & 1) != 0) {
				bits.set(i);
			}
			n = n >>> 1;
		}
		return bits;
	}
}