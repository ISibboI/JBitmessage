package de.flexiprovider.pqc.pflash;

import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.math.IntegerFunctions;
import de.flexiprovider.common.math.codingtheory.GF2mField;

/**
 * <p>
 * This class provides the specification of the parameters used by the
 * {@link PFlashKeyPairGenerator}.
 * </p>
 * <p>
 * <b>The default values for the parameters are :</b><br/>
 * <table border="1">
 * <tr><td>degree of extension m</td><td>=</td><td>4</td></tr>
 * <tr><td>field polynomial of GF(2<sup>m</sup>)</td><td>=</td><td>X<sup>4</sup> + X + 1</td></tr>
 * <tr><td>extension degree of E/K</td><td>=</td><td>96</td></tr>
 * <tr><td>&#945</td><td>=</td><td>32</td></tr>
 * <tr><td>r</td><td>=</td><td>32</td></tr>
 * <tr><td>s</td><td>=</td><td>1</td></tr>
 * </table>
 *
 * @author Marian Hornschuch, Alexander Koller
 */
public class PFlashKeyGenParameterSpec implements AlgorithmParameterSpec {

    /**
     * the default extension degree
     */
    public static final int DEFAULT_m = 4;
    
    /**
     * the default dimension of K<sup>n</sup>
     */
    public static final int DEFAULT_n = 96;
    
    /**
     * the default value of &#945
     */
    public static final int DEFAULT_alpha = 32;
    
    /**
     * the default value of r
     */
    public static final int DEFAULT_r = 32;
    
    /**
     * the default value of s
     */
    public static final int DEFAULT_s = 1;
    
    /**
     * the default field Polynomial : X<sup>4</sup> + X + 1 = 10011<sub>bin</sub> = 19<sub>10</sub>
     */
    public static final int DEFAULT_fieldPoly = 19;

    /**
     * extension degree of E/K
     */
    private int n;
    
    /**
     * the parameter &#945, r, s
     */
    private int alpha, r, s;
    
    /**
     * the field GF(2<sup>m</sup>)
     */
    private GF2mField field;
    
    /**
     * Constructor with default settings.
     */
    public PFlashKeyGenParameterSpec() {
	this(DEFAULT_fieldPoly, DEFAULT_n, DEFAULT_alpha, DEFAULT_r, DEFAULT_s);
    }
    
    /**
     * Constructs new pFLASH parameters. (not supported)
     * 
     * @param p
     * 		field polynomial for the finite field GF(2<sup>m</sup>)
     * @param n
     * 		extension degree of E/K
     * @param alpha
     * 		parameter of the map F: F(x)=x<sup>1+q<sup>&#945</sup></sup>
     * @param r
     * @param s
     */
    public PFlashKeyGenParameterSpec(int p, int n, int alpha, int r, int s) {
	this(new GF2mField(IntegerFunctions.ceilLog(p)-1, p), n, alpha, r, s);
    }
    
    /**
     * Constructs new pFLASH parameters. (not supported)
     * 
     * @param field
     * 		the finite field GF(2<sup>m</sup>)
     * @param n
     * 		extension degree of E/K
     * @param alpha
     * 		parameter of the map F: F(x)=x<sup>1+q<sup>&#945</sup></sup>
     * @param r
     * @param s
     */
    public PFlashKeyGenParameterSpec(GF2mField field, int n, int alpha, int r, int s) {
	this.field = field;
	this.n = n;
	this.alpha = alpha;
	this.r = r;
	this.s = s;
    }
    
    public GF2mField getField() {
	return field;
    }
    
    public int getN() {
	return n;
    }
    
    public int getAlpha() {
	return alpha;
    }
    
    public int getR() {
	return r;
    }
    
    public int getS() {
	return s;
    }
}

