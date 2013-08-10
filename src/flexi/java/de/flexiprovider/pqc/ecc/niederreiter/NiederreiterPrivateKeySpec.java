package de.flexiprovider.pqc.ecc.niederreiter;

import de.flexiprovider.api.keys.KeySpec;
import de.flexiprovider.common.math.codingtheory.GF2mField;
import de.flexiprovider.common.math.codingtheory.PolynomialGF2mSmallM;
import de.flexiprovider.common.math.linearalgebra.GF2Matrix;
import de.flexiprovider.common.math.linearalgebra.Permutation;

/**
 * This class provides a specification for a Niederreiter private key.
 * 
 * @author Elena Klintsevich
 * @see de.flexiprovider.pqc.ecc.niederreiter.NiederreiterPrivateKey
 * @see KeySpec
 */
public class NiederreiterPrivateKeySpec implements KeySpec {

    /**
     * extension degree of the field
     */
    private int m;

    /**
     * dimension of the code, <tt>k &gt;= n-mt</tt>
     */
    private int k;

    /**
     * extension field
     */
    private GF2mField field;

    /**
     * irreducible Goppa polynomial
     */
    private PolynomialGF2mSmallM gp;

    /**
     * the matrix for computing square roots in <tt>(GF(2^m))^t</tt>
     */
    private PolynomialGF2mSmallM[] qInv;

    /**
     * <tt>k x k</tt> random binary non-singular matrix
     */
    private GF2Matrix sInv;

    /**
     * permutation vector
     */
    private Permutation p;

    /**
     * Constructor.
     * 
     * @param m
     *                extension degree of the field
     * @param k
     *                dimension of the code
     * @param field
     *                finite field
     * @param gp
     *                irreducible Goppa polynomial
     * @param sInv
     *                random non-singular matrix S<sup>-1</sup>
     * @param p
     *                permutation vector P
     * @param qInv
     *                matrix used to compute square roots in
     *                <tt>(GF(2<sup>m</sup>))<sup>t</sup></tt>
     */
    public NiederreiterPrivateKeySpec(int m, int k, GF2mField field,
	    PolynomialGF2mSmallM gp, GF2Matrix sInv, Permutation p,
	    PolynomialGF2mSmallM[] qInv) {
	this.k = k;
	this.m = m;
	this.field = field;
	this.gp = gp;
	this.p = p;
	this.sInv = sInv;
	this.qInv = qInv;
    }

    /**
     * Constructor, used by {@link NiederreiterKeyFactory}.
     * 
     * @param m
     *                extension degree of the field
     * @param k
     *                dimension of the code
     * @param encField
     *                encoded finite field
     * @param encGoppaPoly
     *                encoded irreducible Goppa polynomial
     * @param encS
     *                encoded k x k random binary non-singular matrix
     * @param encP
     *                encoded permutation vector
     * @param encQInv
     *                encoded matrix used to compute square roots in
     *                <tt>(GF(2<sup>m</sup>))<sup>t</sup></tt>
     */
    protected NiederreiterPrivateKeySpec(int m, int k, byte[] encField,
	    byte[] encGoppaPoly, byte[] encS, byte[] encP, byte[][] encQInv) {
	this.k = k;
	this.m = m;
	this.field = new GF2mField(encField);
	this.gp = new PolynomialGF2mSmallM(field, encGoppaPoly);
	this.p = new Permutation(encP);
	this.sInv = new GF2Matrix(encS);
	qInv = new PolynomialGF2mSmallM[encQInv.length];
	for (int i = 0; i < encQInv.length; i++) {
	    qInv[i] = new PolynomialGF2mSmallM(field, encQInv[i]);
	}
    }

    /**
     * @return the extension degree of the finite field
     */
    public int getM() {
	return m;
    }

    /**
     * @return the dimension of the code
     */
    public int getK() {
	return k;
    }

    /**
     * @return the finite field
     */
    public GF2mField getField() {
	return field;
    }

    /**
     * @return the irreducible Goppa polynomial
     */
    public PolynomialGF2mSmallM getGoppaPoly() {
	return gp;
    }

    /**
     * @return the random non-singular matrix S<sup>-1</sup>
     */
    public GF2Matrix getSInv() {
	return sInv;
    }

    /**
     * @return the permutation P
     */
    public Permutation getP() {
	return p;
    }

    /**
     * @return the matrix used to compute square roots in
     *         <tt>(GF(2<sup>m</sup>))<sup>t</sup></tt>
     */
    public PolynomialGF2mSmallM[] getQInv() {
	return qInv;
    }

}
