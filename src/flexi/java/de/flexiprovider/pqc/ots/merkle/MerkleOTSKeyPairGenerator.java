package de.flexiprovider.pqc.ots.merkle;

import de.flexiprovider.api.MessageDigest;
import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.exceptions.NoSuchAlgorithmException;
import de.flexiprovider.api.keys.KeyPair;
import de.flexiprovider.api.keys.KeyPairGenerator;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.math.IntegerFunctions;
import de.flexiprovider.core.md.SHA1;
import de.flexiprovider.core.md.SHA256;
import de.flexiprovider.core.md.SHA384;
import de.flexiprovider.core.md.SHA512;

/**
 * This class generates a private and public key for the MerkleOTS (One Time
 * Signature). The private key is a 2-dimensional byte array of random values
 * that are generated with a secure random generator. The secure random
 * generator is initiated before with a seed that can be set with the integer
 * value startValue. The public key is a 2-dimensional byte array with the hash
 * values of the private key. A key pair consists of a
 * {@link MerkleOTSPublicKey} and a {@link MerkleOTSPrivateKey}.
 * <p>
 * A MerkleOTS key pair can be generated as follows:
 * 
 * <pre>
 * // obtain an instance of the key pair generator 
 * KeyPairGenerator kpg = KeyPairGenerator.getInstance(
 * 	&quot;MerkleOTSwithSHA256andSHA1PRNG&quot;, &quot;FlexiPQC&quot;);
 * // set the seed size
 * kpg.initialize(256);
 * // generate the key pair 
 * KeyPair keyPair = kpg.generateKeyPair();
 * </pre>
 * 
 * @author Klintsevich Elena
 * @see MerkleOTSPrivateKey
 * @see MerkleOTSPublicKey
 */
public class MerkleOTSKeyPairGenerator extends KeyPairGenerator {

    // the OID of the algorithm
    private String oid;

    // the hash function
    private MessageDigest md;

    // the hash length
    private int mdLength;

    // the name of the PRNG
    private String prngName;

    // the source of randomness
    private SecureRandom sr;

    // flag indicating whether the key pair generator has been initialized
    private boolean initialized = false;

    // //////////////////////////////////////////////////////////////////////////////

    /*
     * Inner classes providing concrete implementations of OTSKeyPairGenerator
     * with a variety of message digests.
     */

    /**
     * Merkle OTS key pair generator with SHA1 and SHA1PRNG
     */
    public static class SHA1andSHA1PRNG extends MerkleOTSKeyPairGenerator {

	/**
	 * The OID of the algorithm
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.1.1.1";

	/**
	 * Constructor.
	 */
	public SHA1andSHA1PRNG() {
	    super(OID, new SHA1(), "SHA1PRNG");
	}
    }

    /**
     * Merkle OTS key pair generator with SHA256 and SHA1PRNG
     */
    public static class SHA256andSHA1PRNG extends MerkleOTSKeyPairGenerator {

	/**
	 * The OID of the algorithm
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.1.1.2";

	/**
	 * Constructor.
	 */
	public SHA256andSHA1PRNG() {
	    super(OID, new SHA256(), "SHA1PRNG");
	}
    }

    /**
     * Merkle OTS key pair generator with SHA384 and SHA1PRNG
     */
    public static class SHA384andSHA1PRNG extends MerkleOTSKeyPairGenerator {

	/**
	 * The OID of the algorithm
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.1.1.3";

	/**
	 * Constructor.
	 */
	public SHA384andSHA1PRNG() {
	    super(OID, new SHA384(), "SHA1PRNG");
	}
    }

    /**
     * Merkle OTS key pair generator with SHA512 and SHA1PRNG
     */
    public static class SHA512andSHA1PRNG extends MerkleOTSKeyPairGenerator {

	/**
	 * The OID of the algorithm
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.1.1.4";

	/**
	 * Constructor.
	 */
	public SHA512andSHA1PRNG() {
	    super(OID, new SHA512(), "SHA1PRNG");
	}
    }

    // //////////////////////////////////////////////////////////////////////////////

    /**
     * Constructor.
     * 
     * @param oid
     *                the OID of the algorithm
     * @param md
     *                the message digest
     * @param prngName
     *                the name of the PRNG
     */
    protected MerkleOTSKeyPairGenerator(String oid, MessageDigest md,
	    String prngName) {
	this.oid = oid;
	this.md = md;
	mdLength = md.getDigestLength();
	this.prngName = prngName;
    }

    /**
     * Initialize the key pair generator.
     * 
     * @param params
     *                the parameters
     * @param random
     *                the source of randomness
     * @throws InvalidAlgorithmParameterException
     *                 if the parameters are not an instance of
     *                 {@link MerkleOTSKeyGenParameterSpec}.
     */
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
	    throws InvalidAlgorithmParameterException {

	// if no parameters are specified
	if (params == null) {
	    // generate seed of the default length
	    initialize(mdLength << 3, random);
	    return;
	}

	if (!(params instanceof MerkleOTSKeyGenParameterSpec)) {
	    throw new InvalidAlgorithmParameterException("unsupported type");
	}

	// obtain the seed from the parameters
	byte[] seed = ((MerkleOTSKeyGenParameterSpec) params).getSeed();
	// seed the PRNG with the seed
	seedPRNG(seed);

	initialized = true;
    }

    /**
     * Initialize the key pair generator with the given seed size and source of
     * randomness.
     * 
     * @param seedSize
     *                the seed size in bits (&gt;= hash length)
     * @param random
     *                the source of randomness
     */
    public void initialize(int seedSize, SecureRandom random) {
	// set seed size in bytes (must be >= hash length)
	int s = Math.max(seedSize >> 3, mdLength);

	// generate seed of the desired length
	SecureRandom sr = random != null ? random : Registry.getSecureRandom();
	byte[] seed = sr.generateSeed(s);
	// seed the PRNG with the generated seed
	seedPRNG(seed);

	initialized = true;
    }

    private void initializeDefault() {
	initialize(mdLength << 3, Registry.getSecureRandom());
    }

    /**
     * Generate a MerkleOTS key pair, consisting of a {@link MerkleOTSPublicKey}
     * and a {@link MerkleOTSPrivateKey}.
     * 
     * @return the generated key pair
     */
    public KeyPair genKeyPair() {
	if (!initialized) {
	    initializeDefault();
	}

	// compute the private and public key sizes
	int logs = IntegerFunctions.ceilLog(mdLength) + 4;
	logs >>= 3;
	logs++;
	int keySize = (mdLength + logs) << 3;

	byte[][] privKeyBytes = new byte[keySize][mdLength];
	byte[][] pubKeyBytes = new byte[keySize][mdLength];

	for (int i = 0; i < keySize; i++) {
	    // generate random private key bytes
	    sr.nextBytes(privKeyBytes[i]);

	    // hash the private key bytes to obtain the public key bytes
	    pubKeyBytes[i] = md.digest(privKeyBytes[i]);
	}

	// generate the key instances and return the key pair
	MerkleOTSPublicKey pubKey = new MerkleOTSPublicKey(oid, pubKeyBytes);
	MerkleOTSPrivateKey privKey = new MerkleOTSPrivateKey(oid, privKeyBytes);

	return new KeyPair(pubKey, privKey);
    }

    private void seedPRNG(byte[] seed) {
	try {
	    sr = Registry.getSecureRandom(prngName);
	} catch (NoSuchAlgorithmException nsae) {
	    throw new RuntimeException("Secure random '" + prngName
		    + "' not found.");
	}
	sr.setSeed(seed);
    }

}
