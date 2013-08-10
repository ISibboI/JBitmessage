package de.flexiprovider.core.pbe.interfaces;

import de.flexiprovider.api.keys.KeySpec;
import de.flexiprovider.api.keys.SecretKeyFactory;
import de.flexiprovider.core.pbe.PBEKeySpec;

public abstract class PBEKeyFactory extends SecretKeyFactory {

    protected javax.crypto.SecretKey engineGenerateSecret(
	    java.security.spec.KeySpec keySpec)
	    throws java.security.spec.InvalidKeySpecException {

	if ((keySpec == null) || !(keySpec instanceof KeySpec)
		&& (keySpec instanceof javax.crypto.spec.PBEKeySpec)) {
	    PBEKeySpec pbeKeySpec = new PBEKeySpec(
		    (javax.crypto.spec.PBEKeySpec) keySpec);
	    return super.engineGenerateSecret(pbeKeySpec);
	}

	return super.engineGenerateSecret(keySpec);
    }

}
