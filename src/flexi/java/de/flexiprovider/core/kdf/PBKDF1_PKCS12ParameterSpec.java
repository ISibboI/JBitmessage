package de.flexiprovider.core.kdf;

import de.flexiprovider.core.pbe.PBEParameterSpec;

/**
 * This class provides a specification for the parameters used by the PBKDF1 key
 * derivation function specified in <a
 * href="http://www.rsa.com/rsalabs/node.asp?id=2138">PKCS #12 v1.0</a>. The
 * parameters consist of a salt, an iteration count, and a purpose
 * identification byte.
 */
public class PBKDF1_PKCS12ParameterSpec extends PBEParameterSpec {

    /**
     * Constant identifying use for encryption/decryption.
     */
    public static final byte ID_ENCRYPTION = 1;

    /**
     * Constant identifying use for generating IVs.
     */
    public static final byte ID_IV = 2;

    /**
     * Constant identifying use for integrity protection.
     */
    public static final byte ID_INTEGRITY = 3;

    // the purpose identification byte
    private byte id;

    /**
     * Construct new PBKDF1 parameters using the given salt, iteration count,
     * and purpose identification byte.
     * 
     * @param salt
     *                the salt
     * @param iterationCount
     *                the iteration count
     * @param id
     *                the purpose identification byte
     */
    public PBKDF1_PKCS12ParameterSpec(byte[] salt, int iterationCount, byte id) {
	super(salt, iterationCount);
	this.id = id;
    }

    /**
     * @return the purpose identification byte
     */
    public byte getID() {
	return id;
    }

}
