package de.flexiprovider.pqc.pflash;

import de.flexiprovider.api.keys.KeySpec;
import de.flexiprovider.common.math.codingtheory.GF2mField;
import de.flexiprovider.common.math.finitefields.GF2Polynomial;
import de.flexiprovider.common.math.linearalgebra.GF2mMatrix;
import de.flexiprovider.common.math.linearalgebra.GF2mVector;

/**
 * This class provides a specification for a pFLASH private key.
 *
 * @author Marian Hornschuch, Alexander Koller
 * @see PFlashPrivateKey
 * @see KeySpec
 */
public class PFlashPrivateKeySpec implements KeySpec {

    // the OID of the algorithm
    private String oid;
    
    // GF(2^4) with field polynomial X^4+X+1 
    private final GF2mField field = new GF2mField(4, 19);
    
    // map S = M_S + c_S
    private GF2mMatrix m_S;
    
    private GF2mVector c_S;

    // map T = M_T + c_T
    private GF2mMatrix m_T;
    
    private GF2mVector c_T;
    
    // field polynomial of GF(2^(4*96))
    private GF2Polynomial poly_384;
    
    public PFlashPrivateKeySpec(GF2mMatrix m_S, GF2mVector c_S,
	     GF2mMatrix m_T, GF2mVector c_T, GF2Polynomial poly_384) {
	 this.m_S = m_S;
	 this.c_S = c_S;
	 this.m_T = m_T;
	 this.c_T = c_T;
	 this.poly_384 = poly_384;
    }
    
    protected PFlashPrivateKeySpec(byte[] m_S, byte[] c_S,
	    byte[] m_T, byte[] c_T, byte[] poly_384) {
	this.m_S = new GF2mMatrix(field, m_S);
	this.c_S = new GF2mVector(field, c_S);
	this.m_T = new GF2mMatrix(field, m_T);
	this.c_T = new GF2mVector(field, c_T);
	this.poly_384 = new GF2Polynomial(385, poly_384);
    }
    
    public String getOIDString() {
	return oid;
    }
    
    public GF2mMatrix getM_S() {
	return m_S;
    }
    
    public GF2mVector getC_S() {
	return c_S;
    }
    
    public GF2mMatrix getM_T() {
	return m_T;
    }
    
    public GF2mVector getC_T() {
	return c_T;
    }
    
    public GF2Polynomial getPoly_384() {
	return poly_384;
    }
}
