package de.flexiprovider.pqc.pflash;

import de.flexiprovider.api.keys.KeySpec;

/**
 * This class provides a specification for a pFLASH public key.
 *
 * @author Marian Hornschuch, Alexander Koller
 * @see PFlashPublicKey
 * @see KeySpec
 */
public class PFlashPublicKeySpec implements KeySpec {
    
    // the OID of the algorithm
    private String oid;
    
    // FIXME the keyBytes
    private byte[][] keyBytes;
    
    public PFlashPublicKeySpec(String oid, byte[][] keyBytes) {
	// FIXME
	this.oid = oid;
	this.keyBytes = keyBytes;
    }
    
    public String getOIDString() {
	return oid;
    }
    
    // FIXME getter-Methoden für "n-r quadratic polynomials in n-s variables" 
}
