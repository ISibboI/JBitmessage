package de.flexiprovider.core.dsa.interfaces;

import de.flexiprovider.api.keys.KeyFactory;
import de.flexiprovider.api.keys.KeySpec;
import de.flexiprovider.core.dsa.DSAPrivateKeySpec;
import de.flexiprovider.core.dsa.DSAPublicKeySpec;

public abstract class DSAKeyFactory extends KeyFactory {

    /**
     * JCA adapter for FlexiAPI method generatePublic(): generates a public key
     * object from the provided key specification (key material).
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
		&& (keySpec instanceof java.security.spec.DSAPublicKeySpec)) {
	    KeySpec dsaKeySpec = new DSAPublicKeySpec(
		    (java.security.spec.DSAPublicKeySpec) keySpec);
	    return super.engineGeneratePublic(dsaKeySpec);
	}

	return super.engineGeneratePublic(keySpec);
    }

    /**
     * JCA adapter for FlexiAPI method generatePrivate(): generate a private key
     * object from the provided key specification (key material).
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

	if (keySpec != null && !(keySpec instanceof KeySpec)
		&& (keySpec instanceof java.security.spec.DSAPrivateKeySpec)) {
	    KeySpec dsaKeySpec = new DSAPrivateKeySpec(
		    (java.security.spec.DSAPrivateKeySpec) keySpec);
	    return super.engineGeneratePrivate(dsaKeySpec);
	}

	return super.engineGeneratePrivate(keySpec);
    }
}
