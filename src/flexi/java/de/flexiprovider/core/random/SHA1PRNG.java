package de.flexiprovider.core.random;

import java.security.NoSuchProviderException;

import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.exceptions.NoSuchAlgorithmException;

public class SHA1PRNG extends SecureRandom {

    private java.security.SecureRandom javaRand;

    public SHA1PRNG() throws NoSuchAlgorithmException {
	try {
	    javaRand = java.security.SecureRandom
		    .getInstance("SHA1PRNG", "SUN");
	} catch (java.security.NoSuchAlgorithmException e) {
	    throw new NoSuchAlgorithmException(e.getMessage());
	} catch (NoSuchProviderException e) {
	    throw new NoSuchAlgorithmException(e.getMessage());
	}
    }

    public byte[] generateSeed(int numBytes) {
	return javaRand.generateSeed(numBytes);
    }

    public void nextBytes(byte[] bytes) {
	javaRand.nextBytes(bytes);
    }

    public void setSeed(byte[] seed) {
	javaRand.setSeed(seed);
    }

}
