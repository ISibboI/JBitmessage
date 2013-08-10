package de.flexiprovider.core.kdf;

import de.flexiprovider.api.KeyDerivation;
import de.flexiprovider.api.MessageDigest;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.util.ByteUtils;

/**
 * This class implements the PBKDF1 key derivation function specified in <a
 * href="http://www.rsa.com/rsalabs/node.asp?id=2138">PKCS #12 v1.0</a>. This
 * key derivation function is based on PBKDF1 specified in <a
 * href="http://www.rsa.com/rsalabs/node.asp?id=2127">PKCS #5 v2.0</a>.
 * 
 * @author Martin Döring
 */
public abstract class PBKDF1_PKCS12 extends KeyDerivation {

    // the underlying message digest
    private MessageDigest md;

    // the block size in bytes of the message digest
    private int v;

    // the secret
    private byte[] secret;

    // the salt
    private byte[] salt;

    // the iteration count
    private int iterationCount;

    // the purpose identification byte
    private byte id;

    /*
     * Inner classes providing concrete implementations of PBKDF_PKCS12 with a
     * variety of message digests.
     */

    public static final class MD5 extends PBKDF1_PKCS12 {
	public MD5() {
	    super(new de.flexiprovider.core.md.MD5(), 64);
	}
    }

    public static final class SHA1 extends PBKDF1_PKCS12 {
	public SHA1() {
	    super(new de.flexiprovider.core.md.SHA1(), 64);
	}
    }

    /**
     * Constructor. Set the message digest and its block size in bytes.
     * 
     * @param md
     *                the message digest
     * @param v
     *                the block size in bytes of the message digest
     */
    protected PBKDF1_PKCS12(MessageDigest md, int v) {
	this.md = md;
	this.v = v;
    }

    /**
     * Initialize this KDF with a secret and parameters. The supported
     * parameters type is {@link PBKDF1_PKCS12ParameterSpec}.
     * 
     * @param secret
     *                the secret from which to derive the key
     * @param params
     *                the parameters
     * @throws InvalidKeyException
     *                 if the secret is <tt>null</tt>.
     * @throws InvalidAlgorithmParameterException
     *                 if the parameters are not an instance of
     *                 {@link PBKDF1_PKCS12ParameterSpec}.
     */
    public void init(byte[] secret, AlgorithmParameterSpec params)
	    throws InvalidKeyException, InvalidAlgorithmParameterException {

	// assure that secret is not null
	if (secret == null) {
	    throw new InvalidKeyException("null");
	}
	this.secret = ByteUtils.clone(secret);

	// check parameters type
	if (!(params instanceof PBKDF1_PKCS12ParameterSpec)) {
	    throw new InvalidAlgorithmParameterException("unsupported type");
	}
	PBKDF1_PKCS12ParameterSpec kdfParams = (PBKDF1_PKCS12ParameterSpec) params;

	salt = kdfParams.getSalt();
	iterationCount = kdfParams.getIterationCount();
	id = kdfParams.getID();
    }

    /**
     * Start the derivation process and return the derived key. If supported by
     * the concrete implementation, the derived key will be of the specified
     * length.
     * 
     * @param keySize
     *                the desired length of the derived key
     * @return the derived key with the specified length, or <tt>null</tt> if
     *         the key size is <tt>&lt; 0</tt>.
     */
    public byte[] deriveKey(int keySize) {
	if (keySize < 0) {
	    return null;
	}

	// v = 64 bytes
	// Construct a string, D (the "diversifier") by concatenating
	// v/8 copies of of ID. ID is 1, if the derived bits are to
	// be used for encryption or decryption.
	byte[] mD = new byte[64];
	for (int i = 0; i < mD.length; i++) {
	    mD[i] = id;
	}

	// Concatenate copies of the salt/password to create a string S
	// (or P)of length v * ceil(s (or p)/v).
	byte[] mP = augment(secret);
	byte[] mS = augment(salt);

	// Concatenate S and P to obtain a string I = S||P.
	byte[] mI = ByteUtils.concatenate(mS, mP);

	// the pseudo-random bitstring
	byte[] mA;
	byte[] outCut = new byte[keySize];

	int k = 1;
	do {
	    // compute H(H(H(...H(D||I))))
	    md.update(mD);
	    md.update(mI);
	    mA = md.digest();

	    for (int i = 1; i < iterationCount; i++) {
		md.update(mA);
		mA = md.digest();
	    }

	    // if we have enough bits in the first round, copy them to the
	    // output array and leave the loop.
	    if (keySize < mA.length) {
		System.arraycopy(mA, 0, outCut, 0, keySize);
		break;
	    } else if ((keySize < k * mA.length) || (keySize == k * mA.length)) {
		// if we have enough bits after k iterations, copy the remaining
		// bits to the output array and leave the loop.
		int rem = mA.length - (k * mA.length - keySize);
		System.arraycopy(mA, 0, outCut, (k - 1) * mA.length, rem);
		break;
	    } else {
		System.arraycopy(mA, 0, outCut, (k - 1) * mA.length, mA.length);
	    }

	    // concatenate copies of Ai to construct a v-bit string B
	    byte[] mB = augment(mA);

	    // compute Ij = (Ij + B + 1) mod 2^5
	    FlexiBigInt b = new FlexiBigInt(mB);

	    byte[] ij = new byte[64];
	    byte[] modByte = new byte[65];
	    byte[] one = { 1 };
	    System.arraycopy(one, 0, modByte, 0, 1);

	    FlexiBigInt modulo = new FlexiBigInt(modByte);
	    FlexiBigInt tmp = null;

	    for (int j = 0; j < mI.length / 64; j++) {
		System.arraycopy(mI, j << 6, ij, 0, 64);
		FlexiBigInt ivint = new FlexiBigInt(ij);
		tmp = ((b.add(ivint)).add(FlexiBigInt.ONE)).mod(modulo);
		byte[] tmp1 = tmp.toByteArray();
		// bugfix: tmp may have wrapped around.
		for (int l = 0; l < 64; l++) {
		    mI[(j << 6) + l] = ((tmp1.length + l) >= 64) ? tmp1[tmp1.length
			    + l - 64]
			    : 0;
		}
	    }
	    k++;
	} while ((k - 1) * mA.length < keySize);

	return outCut;
    }

    private byte[] augment(byte[] in) {
	int n = in.length;
	int tmp = (n + v - 1) / v;
	int amount = v * tmp;
	int iter = amount / n;
	int rem = amount % n;

	byte[] result = new byte[amount];
	for (int i = 0; i < iter; i++) {
	    System.arraycopy(in, 0, result, i * n, n);
	}
	if (rem != 0) {
	    System.arraycopy(in, 0, result, iter * n, rem);
	}

	return result;
    }

}
