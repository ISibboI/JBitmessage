package de.flexiprovider.pqc.ots.merkle;

import de.flexiprovider.api.MessageDigest;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.Signature;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.keys.PrivateKey;
import de.flexiprovider.api.keys.PublicKey;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.math.IntegerFunctions;
import de.flexiprovider.common.util.ByteUtils;
import de.flexiprovider.core.md.SHA1;
import de.flexiprovider.core.md.SHA256;
import de.flexiprovider.core.md.SHA384;
import de.flexiprovider.core.md.SHA512;

/**
 * This class implements the MerkleOTS (one-time signature scheme). First the
 * message that should be signed, is hashed with a message digest. Then the hash
 * value is concatenate with the value z. z is the quantity of zeros in the bit
 * representation of the hash value of the message. For every bit that is 1 in
 * the bit representation of the concatenation, the corresponding private key
 * part of the OTSPrivateKey is set. For every 0-bit, the corresponding public
 * key part of the MerkleOTSPublicKey is set. So the signature is a
 * concatenation of parts of the private and public key.
 * <p>
 * Verification of a given signature only succeeds if the hash value of the
 * signature is the MerkleOTSPublicKey.
 * <p>
 * The MerkleOTSSignature can be used like the following:
 * 
 * <pre>
 * Signature merkleSign = Signature.getInstance(&quot;MerkleOTSwithSHA256&quot;, &quot;FlexiPQC&quot;);
 * // create signature
 * merkleSign.initSign(privateKey);
 * merkleSign.update(data, 0, data.length);
 * byte[] sign = merkleSign.sign();
 * 
 * // verify signature
 * merkleSign.initVerify(publicKey);
 * merkleSign.update(data, 0, data.length);
 * boolean verify = merkleSign.verify(sign);
 * System.out.println(verify);
 * </pre>
 * 
 * @author Elena Klintsevich
 */
public abstract class MerkleOTSSignature extends Signature {

    // the OID of the algorithm
    private String oid;

    // the message digest
    private MessageDigest md;

    private int mdLength;

    private int keySize;

    private byte[][] pubKeyBytes;

    private byte[][] privKeyBytes;

    // //////////////////////////////////////////////////////////////////////////////

    /*
     * Inner classes providing concrete implementations of MerkleOTSSignature
     * with a variety of message digests.
     */

    /**
     * Merkle OTS signature with SHA1 and SHA1PRNG.
     */
    public static class SHA1andSHA1PRNG extends MerkleOTSSignature {

	/**
	 * The OID of the algorithm
	 */
	public static final String OID = MerkleOTSKeyPairGenerator.SHA1andSHA1PRNG.OID;

	/**
	 * Constructor.
	 */
	public SHA1andSHA1PRNG() {
	    super(OID, new SHA1());
	}
    }

    /**
     * Merkle OTS signature with SHA256 and SHA1PRNG.
     */
    public static class SHA256andSHA1PRNG extends MerkleOTSSignature {

	/**
	 * The OID of the algorithm
	 */
	public static final String OID = MerkleOTSKeyPairGenerator.SHA256andSHA1PRNG.OID;

	/**
	 * Constructor.
	 */
	public SHA256andSHA1PRNG() {
	    super(OID, new SHA256());

	}
    }

    /**
     * Merkle OTS signature with SHA384 and SHA1PRNG.
     */
    public static class SHA384andSHA1PRNG extends MerkleOTSSignature {

	/**
	 * The OID of the algorithm
	 */
	public static final String OID = MerkleOTSKeyPairGenerator.SHA384andSHA1PRNG.OID;

	/**
	 * Constructor.
	 */
	public SHA384andSHA1PRNG() {
	    super(OID, new SHA384());
	}
    }

    /**
     * Merkle OTS signature with SHA512 and SHA1PRNG.
     */
    public static class SHA512andSHA1PRNG extends MerkleOTSSignature {

	/**
	 * The OID of the algorithm
	 */
	public static final String OID = MerkleOTSKeyPairGenerator.SHA512andSHA1PRNG.OID;

	/**
	 * Constructor.
	 */
	public SHA512andSHA1PRNG() {
	    super(OID, new SHA512());
	}
    }

    // //////////////////////////////////////////////////////////////////////////////

    /**
     * Constructor.
     * 
     * @param oid
     *                the OID of the algorithm
     * @param md
     *                name of the message digest
     */
    protected MerkleOTSSignature(String oid, MessageDigest md) {
	this.oid = oid;
	this.md = md;
    }

    /**
     * Initialize the signature algorithm for signing a message.
     * 
     * @param key
     *                the private key of the signer
     * @param random
     *                a source of randomness (not used)
     * @throws InvalidKeyException
     *                 if the key is not an instance of OTSPrivateKey.
     */
    public void initSign(PrivateKey key, SecureRandom random)
	    throws InvalidKeyException {
	if (!(key instanceof MerkleOTSPrivateKey)) {
	    throw new InvalidKeyException("unsupported type");
	}
	MerkleOTSPrivateKey privKey = (MerkleOTSPrivateKey) key;

	// check if OID stored in the key matches algorithm OID
	if (!privKey.getOIDString().equals(oid)) {
	    throw new InvalidKeyException(
		    "invalid key for this MerkleOTS instance");
	}

	// set private key and initialize the other values with initValues()
	privKeyBytes = privKey.getKeyBytes();
	initValues();
    }

    /**
     * Initialize the signature algorithm for verifying a signature.
     * 
     * @param key
     *                the public key of the signer.
     * @throws InvalidKeyException
     *                 if the public key is not an instance of
     *                 MerkleOTSPublicKey.
     */
    public void initVerify(PublicKey key) throws InvalidKeyException {
	if (!(key instanceof MerkleOTSPublicKey)) {
	    throw new InvalidKeyException("unsupported type");
	}
	MerkleOTSPublicKey pubKey = (MerkleOTSPublicKey) key;

	// check if OID stored in the key matches algorithm OID
	if (!pubKey.getOIDString().equals(oid)) {
	    throw new InvalidKeyException(
		    "invalid key for this MerkleOTS instance");
	}

	// set public key and initialize the other values with initValues()
	pubKeyBytes = pubKey.getKeyBytes();
	initValues();
	md.reset();
    }

    /**
     * Initialize this signature engine with the specified parameter set (not
     * used).
     * 
     * @param params
     *                the parameters (not used)
     */
    public void setParameters(AlgorithmParameterSpec params) {
	// parameters are not used
    }

    /**
     * Feed a message byte to the message digest.
     * 
     * @param input
     *                the message byte
     */
    public void update(byte input) {
	md.update(input);
    }

    /**
     * Feed an array of message bytes to the message digest.
     * 
     * @param input
     *                the array of message bytes
     * @param inOff
     *                index of message start
     * @param inLen
     *                number of message bytes
     */
    public void update(byte[] input, int inOff, int inLen) {
	md.update(input, inOff, inLen);
    }

    /**
     * Sign a message.
     * 
     * @return the signature.
     */
    public byte[] sign() {
	byte[] hash = md.digest();

	int counter1 = 0;
	byte[][] helpSig = new byte[keySize][mdLength];
	for (int i = 0; i < hash.length; i++) {
	    if ((hash[i] & 1) == 1) {
		System.arraycopy(privKeyBytes[i << 3], 0, helpSig[counter1], 0,
			mdLength);
		counter1++;
	    }

	    if ((hash[i] & 2) == 2) {
		System.arraycopy(privKeyBytes[(i << 3) + 1], 0,
			helpSig[counter1], 0, mdLength);
		counter1++;
	    }

	    if ((hash[i] & 4) == 4) {
		System.arraycopy(privKeyBytes[(i << 3) + 2], 0,
			helpSig[counter1], 0, mdLength);
		counter1++;
	    }

	    if ((hash[i] & 8) == 8) {
		System.arraycopy(privKeyBytes[(i << 3) + 3], 0,
			helpSig[counter1], 0, mdLength);
		counter1++;
	    }

	    if ((hash[i] & 16) == 16) {
		System.arraycopy(privKeyBytes[(i << 3) + 4], 0,
			helpSig[counter1], 0, mdLength);
		counter1++;
	    }

	    if ((hash[i] & 32) == 32) {
		System.arraycopy(privKeyBytes[(i << 3) + 5], 0,
			helpSig[counter1], 0, mdLength);
		counter1++;
	    }

	    if ((hash[i] & 64) == 64) {
		System.arraycopy(privKeyBytes[(i << 3) + 6], 0,
			helpSig[counter1], 0, mdLength);
		counter1++;
	    }

	    if ((hash[i] & 128) == 128) {
		System.arraycopy(privKeyBytes[(i << 3) + 7], 0,
			helpSig[counter1], 0, mdLength);
		counter1++;
	    }

	}

	int t = mdLength << 3;
	int counter0 = t - counter1;
	while (counter0 != 0) {
	    if ((counter0 & 1) == 1) {
		helpSig[counter1] = new byte[mdLength];
		System.arraycopy(privKeyBytes[t], 0, helpSig[counter1], 0,
			mdLength);
		counter1++;
	    }
	    counter0 >>>= 1;
	    t++;
	}

	byte[] sigBytes = new byte[counter1 * mdLength];
	for (int i = 0; i < counter1; i++) {
	    System.arraycopy(helpSig[i], 0, sigBytes, i * mdLength, mdLength);
	}
	return sigBytes;
    }

    /**
     * Verify a signature.
     * 
     * @param sigBytes
     *                the signature to be verified.
     * @return true if the signature is correct - false otherwise.
     */
    public boolean verify(byte[] sigBytes) {
	int d = sigBytes.length / mdLength;
	byte[] hash = md.digest();

	byte[][] helpSig = new byte[d][mdLength];
	for (int i = 0; i < d; i++) {
	    System.arraycopy(sigBytes, i * mdLength, helpSig[i], 0, mdLength);
	}

	int counter1 = 0;
	for (int i = 0; i < hash.length; i++) {
	    if ((hash[i] & 1) == 1) {
		if (counter1 > d) {
		    return false;
		}
		byte[] test = md.digest(helpSig[counter1]);
		if (!ByteUtils.equals(test, pubKeyBytes[i << 3])) {
		    return false;
		}
		counter1++;

	    }

	    if ((hash[i] & 2) == 2) {
		if (counter1 > d) {
		    return false;
		}
		byte[] test = md.digest(helpSig[counter1]);
		if (!ByteUtils.equals(test, pubKeyBytes[(i << 3) + 1])) {
		    return false;
		}
		counter1++;
	    }

	    if ((hash[i] & 4) == 4) {
		if (counter1 > d) {
		    return false;
		}
		byte[] test = md.digest(helpSig[counter1]);
		if (!ByteUtils.equals(test, pubKeyBytes[(i << 3) + 2])) {
		    return false;
		}
		counter1++;
	    }

	    if ((hash[i] & 8) == 8) {
		if (counter1 > d) {
		    return false;
		}
		byte[] test = md.digest(helpSig[counter1]);
		if (!ByteUtils.equals(test, pubKeyBytes[(i << 3) + 3])) {
		    return false;
		}
		counter1++;
	    }

	    if ((hash[i] & 16) == 16) {
		if (counter1 > d) {
		    return false;
		}
		byte[] test = md.digest(helpSig[counter1]);
		if (!ByteUtils.equals(test, pubKeyBytes[(i << 3) + 4])) {
		    return false;
		}
		counter1++;
	    }

	    if ((hash[i] & 32) == 32) {
		if (counter1 > d) {
		    return false;
		}
		byte[] test = md.digest(helpSig[counter1]);
		if (!ByteUtils.equals(test, pubKeyBytes[(i << 3) + 5])) {
		    return false;
		}
		counter1++;
	    }

	    if ((hash[i] & 64) == 64) {
		if (counter1 > d) {
		    return false;
		}
		byte[] test = md.digest(helpSig[counter1]);
		if (!ByteUtils.equals(test, pubKeyBytes[(i << 3) + 6])) {
		    return false;
		}
		counter1++;
	    }

	    if ((hash[i] & 128) == 128) {
		if (counter1 > d) {
		    return false;
		}
		byte[] test = md.digest(helpSig[counter1]);
		if (!ByteUtils.equals(test, pubKeyBytes[(i << 3) + 7])) {
		    return false;
		}
		counter1++;
	    }

	}

	int t = mdLength << 3;
	int counter0 = t - counter1;
	while (counter0 != 0) {
	    if ((counter0 & 1) == 1) {
		if (counter1 > d) {
		    return false;
		}
		byte[] test = md.digest(helpSig[counter1]);
		if (!ByteUtils.equals(test, pubKeyBytes[t])) {
		    return false;
		}
		counter1++;
	    }
	    counter0 >>>= 1;
	    t++;
	}

	if (counter1 < d) {
	    return false;
	}

	return true;
    }

    /**
     * Initialize the hash length and key size values.
     */
    private void initValues() {
	mdLength = md.getDigestLength();
	int logs = (IntegerFunctions.ceilLog(mdLength) + 4) >>> 3;
	keySize = (mdLength + logs) << 3;
    }

}
