package de.flexiprovider.core.desede;

import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.keys.KeySpec;

/**
 * This class specifies a DES key.
 * 
 */
public class DESKeySpec extends javax.crypto.spec.DESKeySpec implements KeySpec {

    /**
     * Uses the first 8 bytes in key as the key material for the DES key. The
     * bytes that constitute the DES key are those between key[0] and key[7]
     * inclusive.
     * 
     * @param key
     *                the buffer with the DES key material.
     * @throws java.security.InvalidKeyException
     *                 if the given key material is shorter than 8 bytes.
     */
    public DESKeySpec(byte[] key) throws java.security.InvalidKeyException {
	super(key);
    }

    /**
     * Uses the first 8 bytes in key, beginning at offset inclusive, as the key
     * material for the DES key. The bytes that constitute the DES key are those
     * between key[offset] and key[offset+7] inclusive.
     * 
     * @param key
     *                the buffer with the DES key material.
     * @param offset
     *                the offset in key, where the DES key material starts.
     * @throws java.security.InvalidKeyException
     *                 if the given key material, starting at offset inclusive,
     *                 is shorter than 8 bytes.
     */
    public DESKeySpec(byte[] key, int offset)
	    throws java.security.InvalidKeyException {
	super(key, offset);
    }

    /**
     * 
     * @return the DES key material.
     */
    public byte[] getDESKey() {
	return getKey();
    }

    /**
     * Checks if the given DES key material, starting at offset inclusive, is
     * parity-adjusted.
     * 
     * @param key
     *                the buffer with the DES key material.
     * @param offset
     *                the offset in key, where the DES key material starts.
     * @return true if the given DES key material is parity-adjusted, false
     *         otherwise.
     * @throws java.security.InvalidKeyException
     *                 if the given key material, starting at offset inclusive,
     *                 is shorter than 8 bytes.
     */
    public static boolean isParityAdjusted(byte[] key, int offset)
	    throws java.security.InvalidKeyException {
	return javax.crypto.spec.DESKeySpec.isParityAdjusted(key, offset);
    }

    /**
     * Checks if the given DES key material is weak or semi-weak.
     * 
     * @param key
     *                the buffer with the DES key material.
     * @param offset
     *                the offset in key, where the DES key material starts.
     * @return true if the given DES key material is weak or semi-weak, false
     *         otherwise.
     * @throws InvalidKeyException
     *                 if the given key material, starting at offset inclusive,
     *                 is shorter than 8 bytes.
     */
    public static boolean isWeak(byte[] key, int offset)
	    throws InvalidKeyException {
	try {
	    return javax.crypto.spec.DESKeySpec.isWeak(key, offset);
	} catch (java.security.InvalidKeyException e) {
	    throw new InvalidKeyException("The key is shorter than 8 bytes!");
	}
    }
}
