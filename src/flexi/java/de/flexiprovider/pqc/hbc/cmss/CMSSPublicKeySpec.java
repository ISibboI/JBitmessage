package de.flexiprovider.pqc.hbc.cmss;

import de.flexiprovider.api.keys.KeySpec;

/**
 * This class provides a specification for a CMSS public key.
 * 
 * @author Elena Klintsevich
 * 
 * @see de.flexiprovider.pqc.hbc.cmss.CMSSPublicKey
 * @see KeySpec
 */
public class CMSSPublicKeySpec implements KeySpec {

    // the OID of the algorithm
    private String oid;

    // the key bytes
    private byte[] keyBytes;

    // the masks for spr-cmss
    byte[][][] masks;

    /**
     * Construct a new CMSS2 public key.
     * 
     * @param oid
     *                the OID of the algorithm
     * @param keyBytes
     *                the key bytes
     */
    public CMSSPublicKeySpec(String oid, byte[] keyBytes, byte[][][] masks) {
	this.oid = oid;
	this.keyBytes = keyBytes;
	this.masks = masks;
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
    public byte[] getPubKeyBytes() {
	return keyBytes;
    }

    public byte[][][] getMasks() {
	return masks;
    }

}
