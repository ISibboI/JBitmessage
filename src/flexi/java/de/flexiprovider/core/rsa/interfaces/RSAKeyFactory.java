package de.flexiprovider.core.rsa.interfaces;

import de.flexiprovider.api.keys.KeyFactory;
import de.flexiprovider.api.keys.KeySpec;
import de.flexiprovider.core.rsa.RSAPrivateCrtKeySpec;
import de.flexiprovider.core.rsa.RSAPrivateKeySpec;
import de.flexiprovider.core.rsa.RSAPublicKeySpec;

public abstract class RSAKeyFactory extends KeyFactory {

    /**
     * Translation adapter for Java-KeySpecs: generate a public key object from
     * the provided key specification (key material).
     * 
     * @param keySpec
     *                the specification (key material) of the public key
     * @return the public key
     * @throws java.security.spec.InvalidKeySpecException
     *                 if the given key specification is inappropriate for this
     *                 key factory to produce a public key.
     */
    protected java.security.PublicKey engineGeneratePublic(
	    java.security.spec.KeySpec keySpec)
	    throws java.security.spec.InvalidKeySpecException {

	if (keySpec != null && !(keySpec instanceof KeySpec)
		&& (keySpec instanceof java.security.spec.RSAPublicKeySpec)) {
	    KeySpec rsaKeySpec = new RSAPublicKeySpec(
		    (java.security.spec.RSAPublicKeySpec) keySpec);
	    return super.engineGeneratePublic(rsaKeySpec);
	}

	return super.engineGeneratePublic(keySpec);
    }

    /**
     * Translation adapter for Java-KeySpecs: generate a private key object from
     * the provided key specification (key material).
     * 
     * @param keySpec
     *                the specification (key material) of the private key
     * @return the private key
     * @throws java.security.spec.InvalidKeySpecException
     *                 if the given key specification is inappropriate for this
     *                 key factory to produce a private key.
     */
    protected java.security.PrivateKey engineGeneratePrivate(
	    java.security.spec.KeySpec keySpec)
	    throws java.security.spec.InvalidKeySpecException {

	if (keySpec != null && !(keySpec instanceof KeySpec)) {
	    if (keySpec instanceof java.security.spec.RSAPrivateCrtKeySpec) {
		KeySpec rsaKeySpec = new RSAPrivateCrtKeySpec(
			(java.security.spec.RSAPrivateCrtKeySpec) keySpec);
		return super.engineGeneratePrivate(rsaKeySpec);
	    }

	    if (keySpec instanceof java.security.spec.RSAPrivateKeySpec) {
		KeySpec rsaKeySpec = new RSAPrivateKeySpec(
			(java.security.spec.RSAPrivateKeySpec) keySpec);
		return super.engineGeneratePrivate(rsaKeySpec);
	    }
	}

	return super.engineGeneratePrivate(keySpec);
    }
}
