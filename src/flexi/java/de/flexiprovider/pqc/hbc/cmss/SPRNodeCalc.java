package de.flexiprovider.pqc.hbc.cmss;

import java.util.LinkedList;
import java.util.List;
import java.util.ListIterator;

import de.flexiprovider.api.MessageDigest;
import de.flexiprovider.common.util.ByteUtils;

/**
 * This class provides an implementation of the {@link NodeCalc} interface,
 * which calculates nodes in a way, that the use of SPR Hash Functions is
 * secure.
 * 
 */
public class SPRNodeCalc implements NodeCalc {
    private MessageDigest md;
    private byte[][][] masks;
    private int otsMdSize;

    /**
     * Constructs a new {@link SPRNodeCalc} object, that uses the given
     * {@link MessageDigest} and <code>masks</code> to calculate the nodes.
     * The size of the {@link MessageDigest}, that the OTS uses, is necessary
     * to calculate the leafs properly.
     * 
     * @param md
     * @param masks
     * @param otsMdSize
     */
    public SPRNodeCalc(MessageDigest md, byte[][][] masks, int otsMdSize) {
	this.md = md;
	this.masks = masks;
	this.otsMdSize = otsMdSize;
    }

    public byte[] computeParent(byte[] leftNode, byte[] rightNode, int height) {
	if (leftNode == null || rightNode == null
		|| leftNode.length != rightNode.length) {
	    throw new IllegalArgumentException(
		    "Left node and right node must not be null and have the same length.");
	}
	byte[] leftXored = ByteUtils.xor(leftNode, masks[height][0]);
	byte[] rightXored = ByteUtils.xor(rightNode, masks[height][1]);

	md.update(leftXored);
	md.update(rightXored);

	return md.digest();
    }

    public byte[] getLeaf(byte[] vkey) {
	int t = vkey.length / otsMdSize;
	List nodes = new LinkedList();
	for (int i = 0; i < t; i++) {
	    byte[] tmp = new byte[otsMdSize];
	    System.arraycopy(vkey, i * otsMdSize, tmp, 0, otsMdSize);
	    nodes.add(tmp);
	}

	int height = masks.length - 1;
	while (nodes.size() > 1) {
	    List tmp = new LinkedList();
	    ListIterator it = nodes.listIterator();
	    while (it.hasNext()) {
		byte[] left = (byte[]) it.next();
		if (it.hasNext()) {
		    byte[] right = (byte[]) it.next();
		    tmp.add(computeParent(left, right, height));
		} else {
		    tmp.add(left);
		}
	    }
	    nodes = tmp;
	    height--;
	}
	return (byte[]) nodes.get(0);
    }

}
