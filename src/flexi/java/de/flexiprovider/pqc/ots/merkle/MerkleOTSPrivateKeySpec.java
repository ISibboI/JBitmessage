package de.flexiprovider.pqc.ots.merkle;

import de.flexiprovider.api.keys.KeySpec;

/**
 * This class provides a specification for a MerkleOTS key.
 * 
 * @author Klintsevich Elena
 * @see de.flexiprovider.pqc.ots.merkle.MerkleOTSPrivateKey
 * @see de.flexiprovider.pqc.ots.merkle.MerkleOTSPublicKey
 * @see KeySpec
 */
public class MerkleOTSPrivateKeySpec implements KeySpec {

    // the OID of the algorithm
    private String oid;

    // the key bytes
    private byte[][] keyBytes;

    /**
     * Construct a new key specification from the given OID and key bytes.
     * 
     * @param oid
     *                the OID of the algorithm
     * @param keyBytes
     *                the key bytes
     */
    public MerkleOTSPrivateKeySpec(String oid, byte[][] keyBytes) {
	this.oid = oid;
	this.keyBytes = keyBytes;
    }

    /**
     * @return the OID of the algorithm
     */
    public String getOIDString() {
	return oid;
    }

    /**
     * @return the key bytes
     */
    public byte[][] getKeyBytes() {
	return keyBytes;
    }

}
