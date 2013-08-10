package de.flexiprovider.pqc.hbc.cmss;

import de.flexiprovider.api.keys.KeySpec;

/**
 * This class provides a specification for a CMSS private key.
 * 
 * @author Elena Klintsevich;
 * @see de.flexiprovider.pqc.hbc.cmss.CMSSPrivateKey
 * @see KeySpec
 */
public class CMSSPrivateKeySpec implements KeySpec {

    // the OID of the algorithm
    private String oid;

    private int indexMain, indexSub, heightOfTrees;

    private byte[][] seeds;

    private BDSAuthPath[] authPath;
    private int activeSubtree;

    private byte[] subtreeRootSig;

    private byte[] maintreeOTSVerificationKey;

    private byte[][][] masks;

    /**
     * @param oid
     *                the OID of the algorithm
     * @param indexMain
     *                main tree index
     * @param indexSub
     *                subtree index
     * @param heightOfTrees
     *                height of trees
     * @param seeds
     *                seed for generate next OTSKey of Merkle tree and next
     *                Merkle tree
     * @param auth
     *                authentication paths
     * @param subtreeRootSig
     *                the one-time signature of the root of the current subtree
     */
    public CMSSPrivateKeySpec(String oid, int indexMain, int indexSub,
	    int heightOfTrees, byte[][] seeds, BDSAuthPath[] authPath,
	    int activeSubtree, byte[] subtreeRootSig,
	    byte[] maintreeOTSVerificationKey, byte[][][] masks) {

	this.oid = oid;
	this.indexMain = indexMain;
	this.indexSub = indexSub;
	this.heightOfTrees = heightOfTrees;
	this.seeds = seeds;
	this.authPath = authPath;
	this.activeSubtree = activeSubtree;
	this.subtreeRootSig = subtreeRootSig;
	this.maintreeOTSVerificationKey = maintreeOTSVerificationKey;
	this.masks = masks;
    }

    /**
     * @return the OID string identifying the algorithm this kwy was created
     *         with
     */
    public String getOIDString() {
	return oid;
    }

    /**
     * @return the main tree index
     */
    public int getIndexMain() {
	return indexMain;
    }

    /**
     * @return the subtree index
     */
    public int getIndexSub() {
	return indexSub;
    }

    /**
     * @return the height of trees
     */
    public int getHeightOfTrees() {
	return heightOfTrees;
    }

    /**
     * @return the seeds
     */
    public byte[][] getSeeds() {
	return seeds;
    }

    /**
     * @return the authentication paths
     */
    public BDSAuthPath[] getAuthPaths() {
	return authPath;
    }

    /**
     * @return the active subtree
     */
    public int getActiveSubtree() {
	return activeSubtree;
    }

    /**
     * @return the main tree part of signature
     */
    public byte[] getSubtreeRootSig() {
	return subtreeRootSig;
    }

    /**
     * @return the one-time public key used to verify the rootSignature of the
     *         subtree
     */
    public byte[] getMaintreeOTSVerificationKey() {
	return maintreeOTSVerificationKey;
    }

    public byte[][][] getMasks() {
	return masks;
    }

}
