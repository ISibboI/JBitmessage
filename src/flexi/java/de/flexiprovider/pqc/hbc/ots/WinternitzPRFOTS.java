/**
 * 
 */
package de.flexiprovider.pqc.hbc.ots;

import de.flexiprovider.api.MessageDigest;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.util.ByteUtils;
import de.flexiprovider.common.util.FlexiBigIntUtils;
import de.flexiprovider.pqc.hbc.PRNG;

/**
 * @author Sarah
 * 
 *         based on WinternitzOTS by Elena Klintsevich
 */
public class WinternitzPRFOTS implements OTS {

	// the Winternitz parameter
	private int w;

	// the hash function used by the OTS
	private MessageDigest md;

	// the RNG used for key pair generation
	private PRNG rng;

	// the lengths of the message digest, private key, message, and checksum
	private int externMdSize, mdSize, keySize, mSize, cSize, keyLength;

	// the private key bytes
	private byte[][] privKeyBytes;

	// the verification key bytes
	private byte[] pubKeyBytes;

	private boolean canComputeVerificationKeyFromSignature = true;

	// // the default bit security
	// private static final int DEFAULT_BIT_SECURITY = 80;

	private static final int NOT_SET = -1;

	// the desired bit security
	private int bitSecurity = NOT_SET;

	/**
	 * Constructor.
	 * 
	 * @param w
	 *            the Winternitz parameter
	 */
	public WinternitzPRFOTS(int w) {
		this.w = w;
		// this.bitSecurity = DEFAULT_BIT_SECURITY;
	}

	/**
	 * Constructor.
	 * 
	 * @param w
	 *            the Winternitz parameter
	 * @param bitSecurity
	 *            the desired bit security
	 */
	public WinternitzPRFOTS(int w, int bitSecurity) {
		this.w = w;
		this.bitSecurity = bitSecurity;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * de.flexiprovider.pqc.hbc.ots.OTS#canComputeVerificationKeyFromSignature()
	 */
	public boolean canComputeVerificationKeyFromSignature() {
		return canComputeVerificationKeyFromSignature;
	}

	/**
	 * computes the minimal length of the message digest needed to assert the
	 * designated bit security
	 * 
	 * @return the needed length of the message digest
	 */
	private int getNeededMdSize() {
		if (bitSecurity == NOT_SET || bitSecurity >= getMaxBitSecurity()) {
			return externMdSize;
		}
		int b = bitSecurity;
		int mSize = (int) Math.ceil(2.0 * b * (Math.log(2) / Math.log(w)));
		int cSize = (int) Math.floor(Math.log(mSize * (w - 1)) / Math.log(w)) + 1;
		int l = mSize + cSize;
		int tmpBitSecurity = b - w
				- (int) Math.ceil(2.0 * Math.log(l * w) / Math.log(2));
		while (tmpBitSecurity < bitSecurity) {
			b += (bitSecurity - tmpBitSecurity);
			mSize = (int) Math.ceil(2.0 * b * (Math.log(2) / Math.log(w)));
			cSize = (int) Math.floor(Math.log(mSize * (w - 1)) / Math.log(w)) + 1;
			l = mSize + cSize;
			tmpBitSecurity = b - w
					- (int) Math.ceil(2.0 * Math.log(l * w) / Math.log(2));
		}
		// return 2 * b / 8 + (((2 * b % 8) > 0) ? 1 : 0);
		return (b >> 2) + ((b % 4) > 0 ? 1 : 0);
	}

	/**
	 * computes the maximal possible bit security that can be asserted,
	 * according to the given message digest
	 * 
	 * @return the maximal supported bit security of this instance
	 */
	private int getMaxBitSecurity() {
		// int maxB = externMdSize * 8 / 2;
		int maxB = externMdSize << 2;
		int mSize = (int) Math.ceil(2.0 * maxB * (Math.log(2) / Math.log(w)));
		int cSize = (int) Math.floor(Math.log(mSize * (w - 1)) / Math.log(w)) + 1;
		int l = mSize + cSize;
		return maxB - w - (int) Math.ceil(2.0 * Math.log(l * w) / Math.log(2));
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see de.flexiprovider.pqc.hbc.ots.OTS#computeVerificationKey(byte[],
	 * byte[])
	 */
	/**
	 * Compute the OTS verification key from the one-time signature of a
	 * message. This is *NOT* a complete OTS signature verification, but it
	 * suffices for usage with CMSS.
	 * 
	 * @param mBytes
	 *            the message
	 * @param sigBytes
	 *            the one-time signature
	 * @return the OTS verification key
	 */
	public byte[] computeVerificationKey(byte[] mBytes, byte[] sigBytes) {
		if (sigBytes.length != getSignatureLength()) {
			return null;
		}

		// create hash of message m
		MessageDigest wrappedMd = new MessageDigestWrapper(md, mdSize);
		byte[] hash = wrappedMd.digest(mBytes);

		byte[] testKey = new byte[sigBytes.length];

		// compute an integer representation of the message blocks
		// for each message block the corresponding integer denotes how many
		// times the corresponding private key part has been hashed to generate
		// the signature
		int[] mBlocks = convertToBaseW(hash, mSize);

		// compute checksum
		FlexiBigInt checksum = FlexiBigInt.ZERO;
		for (int i = 0; i < mBlocks.length; i++) {
			checksum = checksum.add(FlexiBigInt.valueOf((w - 1 - mBlocks[i])));
		}

		// byte array representation of the checksum
		byte[] checksumBytes = FlexiBigIntUtils.toMinimalByteArray(checksum);

		// compute an integer representation of the checksum blocks
		// for each checksum block the corresponding integer denotes how many
		// times the corresponding private key part has been hashed to generate
		// the signature
		int[] cBlocks = convertToBaseW(checksumBytes, cSize);

		// compute verification key:
		// for each message block i the corresponding signature part is hashed
		// w-1-mBlocks[i] times to compute the verification key

		byte[] help = new byte[2 * keyLength];
		for (int i = 0; i < keyLength; i++) {
			help[i] = 0;
		}

		wrappedMd = new MessageDigestWrapper(md, keyLength);

		for (int i = 0; i < mBlocks.length; i++) {
			byte[] tmpKey = new byte[keyLength];
			System.arraycopy(sigBytes, i * keyLength, tmpKey, 0, keyLength);
			for (int j = 1; j <= w - 1 - mBlocks[i]; j++) {
				// key = h(0 | k)
				System.arraycopy(tmpKey, 0, help, keyLength, keyLength);
				tmpKey = wrappedMd.digest(help);
			}
			System.arraycopy(tmpKey, 0, testKey, i * keyLength, keyLength);
		}
		// for each checksum block i the corresponding signature part is
		// hashed w-1-cBlocks[i] times to compute the verification key
		for (int i = 0; i < cBlocks.length; i++) {
			byte[] tmpKey = new byte[keyLength];
			System.arraycopy(sigBytes, (i + mBlocks.length) * keyLength,
					tmpKey, 0, keyLength);
			for (int j = 1; j <= w - 1 - cBlocks[i]; j++) {
				// key = h(0 | k)
				System.arraycopy(tmpKey, 0, help, keyLength, keyLength);
				tmpKey = wrappedMd.digest(help);
			}
			System.arraycopy(tmpKey, 0, testKey, (i + mBlocks.length)
					* keyLength, keyLength);
		}

		return md.digest(testKey);

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see de.flexiprovider.pqc.hbc.ots.OTS#generateKeyPair(byte[])
	 */
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

	/*
	 * (non-Javadoc)
	 * 
	 * @see de.flexiprovider.pqc.hbc.ots.OTS#generateSignatureKey(byte[])
	 */
	/**
	 * Generate an OTS signature key the given seed and the message digest and
	 * PRNG specified via {@link #init(MessageDigest, PRNG)}.
	 * 
	 * @param seed
	 *            the seed for the PRNG
	 */
	public void generateSignatureKey(byte[] seed) {
		// generate random bytes and assign them to the private key
		privKeyBytes = new byte[keySize][keyLength];

		PRNG wrappedRng = new PRNGWrapper(rng, keyLength);
		for (int i = 0; i < keySize; i++) {
			privKeyBytes[i] = wrappedRng.nextSeed(seed);
		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see de.flexiprovider.pqc.hbc.ots.OTS#generateVerificationKey()
	 */
	/**
	 * Generate an OTS verification key from the previously generated signature
	 * key given the message digest specified via
	 * {@link #init(MessageDigest, PRNG)}.
	 * 
	 */
	public void generateVerificationKey() {

		byte[] help = new byte[2 * keyLength];
		for (int i = 0; i < keyLength; i++) {
			help[i] = 0;
		}

		MessageDigest wrappedMd = new MessageDigestWrapper(md, keyLength);

		byte[] tmpPubKeyBytes = new byte[keySize * keyLength];
		for (int i = 0; i < keySize; i++) {
			// hash w-1 time the private key and assign it to the public key
			System.arraycopy(privKeyBytes[i], 0, help, keyLength, keyLength);
			byte[] tmpKey = wrappedMd.digest(help);
			for (int j = 2; j < w; j++) {
				// key = h(0 | k)
				System.arraycopy(tmpKey, 0, help, keyLength, keyLength);
				tmpKey = wrappedMd.digest(help);
			}
			System.arraycopy(tmpKey, 0, tmpPubKeyBytes, i * keyLength,
					keyLength);
		}
		pubKeyBytes = md.digest(tmpPubKeyBytes);

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see de.flexiprovider.pqc.hbc.ots.OTS#getSignatureLength()
	 */
	/**
	 * @return the length of the one-time signature
	 */
	public int getSignatureLength() {
		return keySize * keyLength;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see de.flexiprovider.pqc.hbc.ots.OTS#getVerificationKey()
	 */
	/**
	 * @return the verification key generated via
	 *         {@link #generateKeyPair(byte[])}
	 */
	public byte[] getVerificationKey() {
		return pubKeyBytes;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see de.flexiprovider.pqc.hbc.ots.OTS#getVerificationKeyLength()
	 */
	public int getVerificationKeyLength() {
		return externMdSize;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * de.flexiprovider.pqc.hbc.ots.OTS#init(de.flexiprovider.api.MessageDigest,
	 * de.flexiprovider.pqc.hbc.PRNG)
	 */
	/**
	 * Initialize the OTS.
	 * 
	 * @param md
	 *            the hash function for the OTS
	 * @param rng
	 *            the RNG used for key pair generation
	 */
	public void init(MessageDigest md, PRNG rng) {
		this.md = md;
		this.rng = rng;
		externMdSize = md.getDigestLength();
		// compute the key sizes for private and public key
		mdSize = getNeededMdSize();
		int mdBits = mdSize << 3;
		mSize = (int) Math.ceil(mdBits * (Math.log(2) / Math.log(w)));
		cSize = (int) Math.floor(Math.log(mSize * (w - 1)) / Math.log(w)) + 1;
		keySize = mSize + cSize;
		keyLength = mdSize / 2;

	}

	/**
	 * converts a value to a number of base w and the given length
	 * 
	 * @param value
	 *            : byte array of the value to be converted
	 * @param length
	 *            : length of number of the value converted to base w
	 * 
	 * @return int array of the cyphers of the number with base w
	 */
	private int[] convertToBaseW(byte[] value, int length) {
		FlexiBigInt intValue = new FlexiBigInt(1, value);
		FlexiBigInt[] wPow = new FlexiBigInt[length];

		wPow[0] = FlexiBigInt.ONE;
		wPow[1] = FlexiBigInt.valueOf(w);
		for (int i = 2; i < length; i++) {
			wPow[i] = wPow[i - 1].multiply(wPow[1]);
		}
		int[] result = new int[length];
		for (int i = length - 1; i >= 0; i--) {
			result[length - 1 - i] = 0;
			int cp = intValue.compareTo(wPow[i]);
			while (cp >= 0) {
				intValue = intValue.subtract(wPow[i]);
				result[length - 1 - i]++;
				cp = intValue.compareTo(wPow[i]);
			}
		}
		return result;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see de.flexiprovider.pqc.hbc.ots.OTS#sign(byte[])
	 */
	/**
	 * Generate a one-time signature of the given message using the private key
	 * generated via {@link #generateKeyPair(byte[])}.
	 * 
	 * @param mBytes
	 *            the message
	 * @return the one-time signature of the message
	 */
	public byte[] sign(byte[] mBytes) {
		byte[] sigBytes = new byte[keySize * keyLength];
		// create hash of message m
		MessageDigest wrappedMd = new MessageDigestWrapper(md, mdSize);
		byte[] hash = wrappedMd.digest(mBytes);
		// compute an integer representation of the message blocks
		// for each message block the corresponding integer denotes the number
		// of hashes needed to generate this part of the signature from the
		// corresponding private key part
		int[] mBlocks = convertToBaseW(hash, mSize);

		// compute checksum
		FlexiBigInt checksum = FlexiBigInt.ZERO;
		for (int i = 0; i < mBlocks.length; i++) {
			checksum = checksum.add(FlexiBigInt.valueOf((w - 1 - mBlocks[i])));
		}

		// byte array representation of the checksum
		byte[] checksumBytes = FlexiBigIntUtils.toMinimalByteArray(checksum);

		// compute an integer representation of the checksum blocks
		// for each checksum block the corresponding integer denotes the number
		// of hashes needed to generate this part of the signature from the
		// corresponding private key part
		int[] cBlocks = convertToBaseW(checksumBytes, cSize);

		// generate signature:
		// for each message block i the corresponding private key part is hashed
		// mBlocks[i] times

		byte[] help = new byte[2 * keyLength];
		for (int i = 0; i < keyLength; i++) {
			help[i] = 0;
		}

		wrappedMd = new MessageDigestWrapper(md, keyLength);

		for (int i = 0; i < mBlocks.length; i++) {
			byte[] tmpKey = new byte[keyLength];
			System.arraycopy(privKeyBytes[i], 0, tmpKey, 0, keyLength);
			for (int j = 1; j <= mBlocks[i]; j++) {
				// key = h(0 | k)
				System.arraycopy(tmpKey, 0, help, keyLength, keyLength);
				tmpKey = wrappedMd.digest(help);
			}
			System.arraycopy(tmpKey, 0, sigBytes, i * keyLength, keyLength);
		}
		// for each checksum block i the corresponding private key part is
		// hashed cBlocks[i] times
		for (int i = 0; i < cBlocks.length; i++) {
			byte[] tmpKey = new byte[keyLength];
			System.arraycopy(privKeyBytes[i + mBlocks.length], 0, tmpKey, 0,
					keyLength);
			for (int j = 1; j <= cBlocks[i]; j++) {
				// key = h(0 | k)
				System.arraycopy(tmpKey, 0, help, keyLength, keyLength);
				tmpKey = wrappedMd.digest(help);
			}
			System.arraycopy(tmpKey, 0, sigBytes, (i + mBlocks.length)
					* keyLength, keyLength);
		}

		return sigBytes;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see de.flexiprovider.pqc.hbc.ots.OTS#verify(byte[], byte[], byte[])
	 */
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
		byte[] tmpPubKey = computeVerificationKey(mBytes, sBytes);
		return ByteUtils.equals(tmpPubKey, pBytes);
	}

}
