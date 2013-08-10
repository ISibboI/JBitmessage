package de.flexiprovider.core.dsa.interfaces;

/**
 * The interface to a DSA public or private key. DSA (Digital Signature
 * Algorithm) is defined in NIST's FIPS-186.
 * 
 * @see DSAParams
 * @see java.security.Key
 * @see java.security.Signature
 */
public interface DSAKey extends java.security.interfaces.DSAKey {

    /**
     * @return the DSA-specific key parameters
     * 
     * @see DSAParams
     */
    DSAParams getParameters();

}
