package de.flexiprovider.pqc.hbc.cmss;

import de.flexiprovider.api.parameters.AlgorithmParameterSpec;

/**
 * This class provides a specification for the CMSS parameters that are used by
 * the {@link CMSSKeyPairGenerator} and {@link CMSSSignature} classes.
 * 
 * @author Elena Klintsevich
 * @author Martin Döring
 * @see CMSSKeyPairGenerator
 * @see CMSSSignature
 * @see AlgorithmParameterSpec
 */
public class CMSSParameterSpec implements AlgorithmParameterSpec {

	// The height of the authentication trees. The number of possible signatures
	// is equal to 2^(2*heightOfTrees).
	private int heightOfTrees;

	// The size in bytes of the seed for the PRNG
	private int seedSize;

	/**
	 * Default constructor. Sets <tt>heightOfTrees = 10</tt>,
	 * <tt>seedSize = 20</tt>.
	 */
	public CMSSParameterSpec() {
		this(10, 20);
	}

	/**
	 * Constructor. Sets <tt>seedSize = 20</tt>.
	 * 
	 * @param heightOfTrees
	 *                the height of the authentication trees
	 */
	public CMSSParameterSpec(int heightOfTrees) {
		this(heightOfTrees, 20);
	}

	/**
	 * Constructor.
	 * 
	 * @param heightOfTrees
	 *                the height of the authentication trees
	 * @param seedSize
	 *                the size in bytes of the seed for the PRNG
	 */
	public CMSSParameterSpec(int heightOfTrees, int seedSize) {
		this.heightOfTrees = heightOfTrees;
		this.seedSize = seedSize;
	}

	/**
	 * @return the height of the authentication trees
	 */
	public final int getHeightOfTrees() {
		return heightOfTrees;
	}

	/**
	 * @return the size in bytes of the seed for the PRNG
	 */
	public final int getSeedSize() {
		return seedSize;
	}

}
