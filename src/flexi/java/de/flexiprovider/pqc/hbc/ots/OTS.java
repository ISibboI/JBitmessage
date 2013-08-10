package de.flexiprovider.pqc.hbc.ots;

import de.flexiprovider.api.MessageDigest;
import de.flexiprovider.pqc.hbc.PRNG;

/**
 * This is an interface for the different one-time signature schemes used by
 * CMSS.
 */
public interface OTS {
	
    /**
     * Initialize the OTS.
     * 
     * @param md
     *                the hash function for the OTS
     * @param rng
     *                the name of the PRNG used for key pair generation
     */
    void init(MessageDigest md, PRNG rng);

    /**
     * Generate an OTS key pair using the given seed and the message digest and
     * PRNG specified via {@link #init(MessageDigest, PRNG)}.
     * 
     * @param seed
     *                the seed for the PRGN
     */
    void generateKeyPair(byte[] seed);

    
	/**
	 * Generate an OTS signature key the given seed and the message digest and
	 * PRNG specified via {@link #init(MessageDigest, PRNG)}.
	 * 
	 * @param seed
	 *                the seed for the PRGN
	 */
	public void generateSignatureKey(byte[] seed);

	/**
	 * Generate an OTS verification key from the previously generated signature key given the message digest
	 * specified via {@link #init(MessageDigest, PRNG)}.
	 * 
	 */
	public void generateVerificationKey();
        
    
    /**
     * @return the verification key generated via {@link #generateKeyPair(byte[])}
     */
    byte[] getVerificationKey();

    /**
     * @return the length of the one-time signature
     */
    int getSignatureLength();

    /**
     * @return the length of the one-time verification key
     */
    int getVerificationKeyLength();
    
    
    /**
     * Generate a one-time signature of the given message using the private key
     * generated via {@link #generateKeyPair(byte[])}.
     * 
     * @param mBytes
     *                the message
     * @return the one-time signature of the message
     */
    byte[] sign(byte[] mBytes);

    /**
     * Verify a one-time signature of the given message using the verification key
     * generated via {@link #generateKeyPair(byte[])}.
     * 
     * @param mBytes
     *                the message
     * @param sBytes
     *                the signature
     * @param pBytes
     *                the verification key
     * @return true if signature is valid and false otherwise
     */
    boolean verify(byte[] mBytes, byte[] sBytes, byte[] pBytes);
    
    
    /**
     * Compute the verification OTS key from the one-time signature of a message. This
     * is *NOT* a complete OTS signature verification, but it suffices for usage
     * with CMSS.
     * 
     * @param mBytes
     *                the message
     * @param sigBytes
     *                the one-time signature
     * @return the verification OTS key
     */
    byte[] computeVerificationKey(byte[] mBytes, byte[] sigBytes);

    /**
     * The verification key of come one-time signature schemes can be computes from the signature.
     * 
     * @return true if that is the case and false otherwise
     */    
    boolean canComputeVerificationKeyFromSignature();
}
