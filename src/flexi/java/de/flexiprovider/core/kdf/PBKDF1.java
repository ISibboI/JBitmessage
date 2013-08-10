package de.flexiprovider.core.kdf;

import de.flexiprovider.api.KeyDerivation;
import de.flexiprovider.api.MessageDigest;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.util.ByteUtils;
import de.flexiprovider.core.pbe.PBEParameterSpec;

/**
 * This class implements the PBKDF1 key derivation function as specified in <a
 * href="http://www.rsa.com/rsalabs/node.asp?id=2127">PKCS #5 v2.0</a>.
 * 
 * @author Martin Döring
 */
public abstract class PBKDF1 extends KeyDerivation {

    // the underlying message digest
    private MessageDigest md;

    // the secret
    private byte[] secret;

    // the salt
    private byte[] salt;

    // the iteration count
    private int iterationCount;

    /*
     * Inner classes providing concrete implementations of PBKDF_PKCS12 with a
     * variety of message digests.
     */

    public static final class MD5 extends PBKDF1 {
	public MD5() {
	    super(new de.flexiprovider.core.md.MD5());
	}
    }

    public static final class SHA1 extends PBKDF1 {
	public SHA1() {
	    super(new de.flexiprovider.core.md.SHA1());
	}
    }

    /**
     * Constructor. Set the message digest.
     * 
     * @param md
     *                the message digest
     */
    protected PBKDF1(MessageDigest md) {
	this.md = md;
    }

    /**
     * Initialize this KDF with a secret and parameters. The supported
     * parameters type is {@link PBEParameterSpec}.
     * 
     * @param secret
     *                the secret from which to derive the key
     * @param params
     *                the parameters
     * @throws InvalidKeyException
     *                 if the secret is <tt>null</tt>.
     * @throws InvalidAlgorithmParameterException
     *                 if the parameters are not an instance of
     *                 {@link PBEParameterSpec}.
     */
    public void init(byte[] secret, AlgorithmParameterSpec params)
	    throws InvalidKeyException, InvalidAlgorithmParameterException {

	// assure that secret is not null
	if (secret == null) {
	    throw new InvalidKeyException("null");
	}
	this.secret = ByteUtils.clone(secret);

	// check parameters type
	if (!(params instanceof PBEParameterSpec)) {
	    throw new InvalidAlgorithmParameterException("unsupported type");
	}
	PBEParameterSpec kdfParams = (PBEParameterSpec) params;

	salt = kdfParams.getSalt();
	iterationCount = kdfParams.getIterationCount();
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

	md.update(secret);
	md.update(salt);
	byte[] out = md.digest();

	for (int i = iterationCount; --i >= 1;) {
	    md.update(out);
	    out = md.digest();
	}

	byte[] keyBytes = new byte[keySize];
	System.arraycopy(out, 0, keyBytes, 0, keySize);
	return keyBytes;
    }

}
