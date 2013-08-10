package de.flexiprovider.pqc.rainbow;

import de.flexiprovider.api.keys.KeySpec;
import de.flexiprovider.pqc.rainbow.util.RainbowUtil;

/**
 * This class provides a specification for a RainbowSignature private key.
 * 
 * @see de.flexiprovider.pqc.rainbow.RainbowPrivateKey
 * @see KeySpec
 * 
 * @author Patrick Neugebauer
 * @author Marius Senftleben
 * @author Tsvetoslava Vateva
 * 
 */
public class RainbowPrivateKeySpec implements KeySpec {

	// the OID of the algorithm
	private String oid;

	/*
	 * invertible affine linear map L1
	 */
	// the inverse of A1, (n-v1 x n-v1 matrix)
	private short[][] A1inv;

	// translation vector of L1
	private short[] b1;

	/*
	 * invertible affine linear map L2
	 */
	// the inverse of A2, (n x n matrix)
	private short[][] A2inv;

	// translation vector of L2
	private short[] b2;

	/*
	 * components of F
	 */
	// the number of Vinegar-variables per layer.
	private int[] vi;

	// contains the polynomials with their coefficients of private map F
	private Layer[] layers;

	/**
	 * Constructor
	 * 
	 * @param oid
	 *            the OID of the algorithm
	 * @param A1inv
	 *            the inverse of A1(the matrix part of the affine linear map L1)
	 *            (n-v1 x n-v1 matrix)
	 * @param b1
	 *            translation vector, part of the linear affine map L1
	 * @param A2inv
	 *            the inverse of A2(the matrix part of the affine linear map L2)
	 *            (n x n matrix)
	 * @param b2
	 *            translation vector, part of the linear affine map L2
	 * @param vi
	 *            the number of Vinegar-variables per layer
	 * @param layers
	 *            the polynomials with their coefficients of private map F
	 */
	protected RainbowPrivateKeySpec(String oid, short[][] A1inv, short[] b1,
			short[][] A2inv, short[] b2, int[] vi, Layer[] layers) {
		this.oid = oid;
		this.A1inv = A1inv;
		this.b1 = b1;
		this.A2inv = A2inv;
		this.b2 = b2;
		this.vi = vi;
		this.layers = layers;
	}

	/**
	 * Constructor used by the {@link RainbowKeyFactory}. It constructs internal
	 * data types out of these bytes got from ASN.1 decoding.
	 * 
	 * @param oid
	 *            the OID of the algorithm
	 * @param A1inv
	 *            the inverse of A1(the matrix part of the affine linear map L1)
	 *            (n-v1 x n-v1 matrix) (in bytes)
	 * @param b1
	 *            translation vector, part of the linear affine map L1 (in
	 *            bytes)
	 * @param A2inv
	 *            the inverse of A2(the matrix part of the affine linear map L2)
	 *            (n x n matrix) (in bytes)
	 * @param b2
	 *            translation vector, part of the linear affine map L1 (in
	 *            bytes)
	 * @param vi
	 *            number of Vinegar-variables per layer (in bytes)
	 * @param coeff_alpha
	 *            alpha-coefficients of the polynomials in this layer (in bytes)
	 * @param coeff_beta
	 *            beta-coefficients of the polynomials in this layer (in bytes)
	 * @param coeff_gamma
	 *            gamma-coefficients of the polynomials in this layer (in bytes)
	 * @param coeff_eta
	 *            eta-coefficients of the polynomials in this layer (in bytes)
	 */
	protected RainbowPrivateKeySpec(String oid, byte[][] A1inv, byte[] b1,
			byte[][] A2inv, byte[] b2, byte[] vi, byte[][][][] coeff_alpha,
			byte[][][][] coeff_beta, byte[][][] coeff_gamma, byte[][] coeff_eta) {

		this.oid = oid;

		// map L1
		this.A1inv = RainbowUtil.convertArray(A1inv);
		this.b1 = RainbowUtil.convertArray(b1);

		// map L2
		this.A2inv = RainbowUtil.convertArray(A2inv);
		this.b2 = RainbowUtil.convertArray(b2);

		// map F
		this.vi = RainbowUtil.convertArraytoInt(vi);
		// create the (vn - 1) layers of F
		int numOfLayers = vi.length - 1;
		this.layers = new Layer[numOfLayers];
		for (int i = 0; i < numOfLayers; i++) {
			Layer l = new Layer(i, vi[i], vi[i + 1], coeff_alpha[i],
					coeff_beta[i], coeff_gamma[i], coeff_eta[i]);
			this.layers[i] = l;

		}
	}

	/**
	 * @return name of the algorithm - "Rainbow"
	 */
	public final String getAlgorithm() {
		return "Rainbow";
	}

	/**
	 * @return the OID string identifying the algorithm.
	 */
	public String getOIDString() {
		return oid;
	}

	/**
	 * Getter for the translation part of the private quadratic map L1.
	 * 
	 * @return b1 the translation part of L1
	 */
	protected short[] getb1() {
		return this.b1;
	}

	/**
	 * Getter for the inverse matrix of A1.
	 * 
	 * @return the A1inv inverse
	 */
	protected short[][] getA1inv() {
		return this.A1inv;
	}

	/**
	 * Getter for the translation part of the private quadratic map L2.
	 * 
	 * @return b2 the translation part of L2
	 */
	protected short[] getb2() {
		return this.b2;
	}

	/**
	 * Getter for the inverse matrix of A2
	 * 
	 * @return the A2inv
	 */
	protected short[][] getA2inv() {
		return this.A2inv;
	}

	/**
	 * Returns the layers contained in the private key
	 * 
	 * @return layers
	 */
	protected Layer[] getLayers() {
		return this.layers;
	}

	/**
	 * /** Returns the array of vi-s
	 * 
	 * @return the vi
	 */
	protected int[] getVi() {
		return vi;
	}

}
