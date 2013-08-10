package de.flexiprovider.pqc.ecc.mceliece;

import de.flexiprovider.api.keys.KeySpec;
import de.flexiprovider.common.math.linearalgebra.GF2Matrix;

/**
 * This class provides a specification for a McEliece CCA2 public key.
 * 
 * @see McElieceCCA2PublicKey
 * @author Elena Klintsevich
 * @author Martin Döring
 */
public class McElieceCCA2PublicKeySpec implements KeySpec {

    // the length of the code
    private int n;

    // the error correction capability of the code
    private int t;

    // the generator matrix
    private GF2Matrix matrixG;

    /**
     * Constructor.
     * 
     * @param n
     *                length of the code
     * @param t
     *                error correction capability
     * @param matrix
     *                generator matrix
     */
    public McElieceCCA2PublicKeySpec(int n, int t, GF2Matrix matrix) {
	this.n = n;
	this.t = t;
	this.matrixG = new GF2Matrix(matrix);
    }

    /**
     * Constructor (used by {@link McElieceKeyFactory}).
     * 
     * @param n
     *                length of the code
     * @param t
     *                error correction capability of the code
     * @param encMatrix
     *                encoded generator matrix
     */
    public McElieceCCA2PublicKeySpec(int t, int n, byte[] encMatrix) {
	this.n = n;
	this.t = t;
	this.matrixG = new GF2Matrix(encMatrix);
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
    public GF2Matrix getMatrixG() {
	return matrixG;
    }

}
