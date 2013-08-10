package de.flexiprovider.pqc.ecc.niederreiter;

import de.flexiprovider.api.keys.KeySpec;
import de.flexiprovider.common.math.linearalgebra.GF2Matrix;

/**
 * This class provides a specification for a Niederreiter public key.
 * 
 * @author Elena Klintsevich
 * @see de.flexiprovider.pqc.ecc.niederreiter.NiederreiterPublicKey
 * @see KeySpec
 */
public class NiederreiterPublicKeySpec implements KeySpec {

    // the length of the code
    private int n;

    // the error correction capability of the code
    private int t;

    // the check matrix
    private GF2Matrix h;

    /**
     * Constructor.
     * 
     * @param n
     *                length of the code
     * @param t
     *                error correction capability of the code
     * @param h
     *                check matrix
     */
    public NiederreiterPublicKeySpec(int n, int t, GF2Matrix h) {
	this.t = t;
	this.n = n;
	this.h = new GF2Matrix(h);
    }

    /**
     * Constructor, used by {@link NiederreiterKeyFactory}.
     * 
     * @param n
     *                length of the code
     * @param t
     *                error correction capability of the code
     * @param encH
     *                encoded check matrix
     */
    protected NiederreiterPublicKeySpec(int n, int t, byte[] encH) {
	this.n = n;
	this.t = t;
	this.h = new GF2Matrix(encH);
    }

    /**
     * @return the length of the code
     */
    public int getN() {
	return n;
    }

    /**
     * @return t - the error correction capability of the code
     */
    public int getT() {
	return t;
    }

    /**
     * @return the check matrix
     */
    public GF2Matrix getH() {
	return h;
    }

}
