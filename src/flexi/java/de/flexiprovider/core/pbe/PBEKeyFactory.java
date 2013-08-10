/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.pbe;

import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.exceptions.InvalidKeySpecException;
import de.flexiprovider.api.keys.KeySpec;
import de.flexiprovider.api.keys.SecretKey;

/**
 * This class represents a factory for secret keys. This class is used to
 * convert PBE keys into a format usable by the FlexiProvider and its intended
 * use is for PBE according to PKCS #5, e.g. PbeWithSHAAnd3_KeyTripleDES_CBC.
 * Currently, this class can only convert from a KeySpec into a Key. The
 * supported KeySpec class is PBEKeySpec.
 * <p>
 * This class should not be instantiated directly, instead use the
 * java.security.KeyFactory interface.
 * 
 * @author Michele Boivin
 */
public class PBEKeyFactory extends
	de.flexiprovider.core.pbe.interfaces.PBEKeyFactory {

    /**
     * Generate a PBE SecretKey object from the provided key specification (key
     * material).
     * 
     * @param keySpec
     *                the specification (key material) of the secret key
     * @return The secret key.
     * @throws InvalidKeySpecException
     *                 if the given key specification is inappropriate for this
     *                 secret-key factory to produce a secret key.
     */
    public final SecretKey generateSecret(KeySpec keySpec)
	    throws InvalidKeySpecException {
	if (!(keySpec instanceof PBEKeySpec)) {
	    throw new InvalidKeySpecException("unsupported type");
	}

	return new PBEKey(((PBEKeySpec) keySpec).getPassword());
    }

    /**
     * Return a specification (key material) of the given key object in the
     * requested format.
     * 
     * @param key
     *                the key
     * @param keySpec
     *                the requested format in which the key material shall be
     *                returned
     * @return the underlying key specification (key material) in the requested
     *         format
     * @throws InvalidKeySpecException
     *                 if the requested key specification is inappropriate for
     *                 the given key, or the given key cannot be dealt with
     *                 (e.g., the given key has an unrecognised format).
     */
    public final KeySpec getKeySpec(SecretKey key, Class keySpec)
	    throws InvalidKeySpecException {
	KeySpec key_Spec;
	if ((keySpec == null) || !keySpec.isAssignableFrom(PBEKeySpec.class)) {
	    throw new InvalidKeySpecException("unsupported type");
	}
	if (key == null) {
	    throw new InvalidKeySpecException("key is null");
	}
	key_Spec = new PBEKeySpec(((PBEKey) key).getKey());

	return key_Spec; // returns the requested KeySpec object
    }

    /**
     * Translate a PBE key object, whose provider may be unknown or potentially
     * untrusted, into a corresponding key object of this key factory. Not
     * currently implemented.
     * 
     * @param key
     *                the key whose provider is unknown or untrusted
     * @return the translated key
     * @throws InvalidKeyException
     *                 if the given key cannot be processed by this key factory.
     */
    public final SecretKey translateKey(SecretKey key)
	    throws InvalidKeyException {
	throw new InvalidKeyException("not implemented");
    }

}
