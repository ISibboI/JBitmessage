package de.flexiprovider.core.mac;

import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.exceptions.InvalidKeySpecException;
import de.flexiprovider.api.keys.KeySpec;
import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.api.keys.SecretKeyFactory;
import de.flexiprovider.api.keys.SecretKeySpec;

public class TwoTrackMacKeyFactory extends SecretKeyFactory {

    public SecretKey generateSecret(KeySpec keySpec)
	    throws InvalidKeySpecException {

	if (keySpec == null) {
	    throw new InvalidKeySpecException("key spec is null");
	}

	if (keySpec instanceof SecretKeySpec) {
	    SecretKeySpec secKeySpec = (SecretKeySpec) keySpec;
	    if (!(secKeySpec.getAlgorithm().equals("TwoTrackMac"))) {
		throw new InvalidKeySpecException("unsupported type");
	    }
	    return new TwoTrackMacKey(secKeySpec.getEncoded());
	}

	throw new InvalidKeySpecException("unsupported type");
    }

    public KeySpec getKeySpec(SecretKey key, Class keySpec)
	    throws InvalidKeySpecException {

	if ((key == null) || !(key instanceof TwoTrackMacKey)) {
	    throw new InvalidKeySpecException("unsupported key type");
	}
	if ((keySpec == null)
		|| !(keySpec.isAssignableFrom(SecretKeySpec.class))) {
	    throw new InvalidKeySpecException("unsupported spec type");
	}

	return new SecretKeySpec(((TwoTrackMacKey) key).getEncoded(),
		"TwoTrackMac");
    }

    public SecretKey translateKey(SecretKey key) throws InvalidKeyException {
	if (!(key instanceof TwoTrackMacKey)) {
	    throw new InvalidKeyException("Unsupported key type.");
	}
	return key;
    }

}
