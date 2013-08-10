package de.flexiprovider.core.desede.interfaces;

import de.flexiprovider.api.keys.KeySpec;
import de.flexiprovider.api.keys.SecretKeyFactory;
import de.flexiprovider.core.desede.DESedeKeySpec;

public abstract class DESedeKeyFactory extends SecretKeyFactory {

    protected javax.crypto.SecretKey engineGenerateSecret(
	    java.security.spec.KeySpec keySpec)
	    throws java.security.spec.InvalidKeySpecException {

	if ((keySpec != null) && !(keySpec instanceof KeySpec)
		&& (keySpec instanceof javax.crypto.spec.DESedeKeySpec)) {
	    DESedeKeySpec desKeySpec = new DESedeKeySpec(
		    (javax.crypto.spec.DESedeKeySpec) keySpec);
	    return super.engineGenerateSecret(desKeySpec);
	}

	return super.engineGenerateSecret(keySpec);
    }

    protected java.security.spec.KeySpec engineGetKeySpec(
	    javax.crypto.SecretKey key, Class keySpec)
	    throws java.security.spec.InvalidKeySpecException {

	if ((keySpec != null)
		&& (keySpec
			.isAssignableFrom(javax.crypto.spec.DESedeKeySpec.class))) {
	    return ((DESedeKeySpec) super.engineGetKeySpec(key,
		    DESedeKeySpec.class)).javaKeySpec;
	}

	return super.engineGetKeySpec(key, keySpec);
    }

}
