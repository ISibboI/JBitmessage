package de.flexiprovider.pqc.ecc.mceliece;

import de.flexiprovider.api.keys.KeySpec;
import de.flexiprovider.common.math.linearalgebra.GF2Matrix;

/**
 * This class provides a specification for a McEliece public key.
 * 
 * @author Elena Klintsevich
 * @see McEliecePublicKey
 */
public class McEliecePublicKeySpec implements KeySpec {

    // the length of the code
    private int n;

    // the error correction capability of the code
    private int t;

    // the generator matrix
    private GF2Matrix g;

    /**
     * Constructor (used by {@link McElieceKeyFactory}).
     * 
     * @param n
     *                the length of the code
     * @param t
     *                the error correction capability of the code
     * @param g
     *                the generator matrix
     */
    public McEliecePublicKeySpec(int n, int t, GF2Matrix g) {
	this.n = n;
	this.t = t;
	this.g = new GF2Matrix(g);
    }

    /**
     * Constructor (used by {@link McElieceKeyFactory}).
     * 
     * @param n
     *                the length of the code
     * @param t
     *                the error correction capability of the code
     * @param encG
     *                the encoded generator matrix
     */
    protected McEliecePublicKeySpec(int t, int n, byte[] encG) {
	this.n = n;
	this.t = t;
	this.g = new GF2Matrix(encG);
    }

    /**
     * @return the length of the code
     */
    public int getN() {
	return n;
    }

    /**
     * @return the error correction capability of the code
     */
    public int getT() {
	return t;
    }

    /**
     * @return the generator matrix
     */
    public GF2Matrix getG() {
	return g;
    }

}
