package de.flexiprovider.pqc.hbc.cmss;

/**
 * This interface provides methods for calculating nodes in a tree.
 * 
 */
public interface NodeCalc {
    /**
     * Calculates the parent node of two children.
     * 
     * @param leftNode
     *                the left child
     * @param rightNode
     *                the right child
     * @param height
     *                the height of the children
     * @return the parent node
     */
    public byte[] computeParent(byte[] leftNode, byte[] rightNode, int height);

    /**
     * Calculates the leaf of a tree from the verification key.
     * 
     * @param vkey
     *                the verification key to calculate the leaf from.
     * @return the leaf
     */
    public byte[] getLeaf(byte[] vkey);
}
