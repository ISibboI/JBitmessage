/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.rc2;

import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.exceptions.InvalidKeySpecException;
import de.flexiprovider.api.keys.KeySpec;
import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.api.keys.SecretKeyFactory;
import de.flexiprovider.api.keys.SecretKeySpec;

/**
 * This class implementes the RC2 key factory. It is used to convert RC2 keys
 * between different formats.
 * 
 * @author Michele Boivin
 */
public class RC2KeyFactory extends SecretKeyFactory {

	/**
	 * Generate an RC2 key object from the provided key specification. The key
	 * specification has to be an instance of {@link SecretKeySpec} of type
	 * "RC2".
	 * 
	 * @param keySpec
	 *            the key specification
	 * @return the secret key
	 * @throws InvalidKeySpecException
	 *             if the key specification is of the wrong type.
	 */
	public SecretKey generateSecret(KeySpec keySpec)
			throws InvalidKeySpecException {

		if (keySpec == null) {
			throw new InvalidKeySpecException("Key specification is null.");
		}

		if (keySpec instanceof SecretKeySpec) {
			SecretKeySpec secKeySpec = (SecretKeySpec) keySpec;
			String algName = secKeySpec.getAlgorithm();
			if (algName.equals(RC2.ALG_NAME) || algName.equals(RC2.RC2_CBC.OID)) {
				return new RC2Key(secKeySpec.getEncoded());
			}
		}

		throw new InvalidKeySpecException("Unsupported key specification type.");
	}

	/**
	 * Return a key specification of the given key object in the requested
	 * format. The format has to be equal to or a superclass of
	 * {@link SecretKeySpec}. The key has to be an instance of {@link RC2Key}.
	 * 
	 * @param key
	 *            the key
	 * @param keySpec
	 *            the requested format in which the key material shall be
	 *            returned
	 * @return the underlying key specification (key material) in the requested
	 *         format
	 * @throws InvalidKeySpecException
	 *             if the requested key specification is inappropriate for the
	 *             given key, or the given key cannot be dealt with (e.g., the
	 *             given key has an unrecognized format).
	 */
	public KeySpec getKeySpec(SecretKey key, Class keySpec)
			throws InvalidKeySpecException {

		if ((keySpec == null)
				|| !(keySpec.isAssignableFrom(SecretKeySpec.class))) {
			throw new InvalidKeySpecException("wrong spec type");
		}
		if ((key == null) || !(key instanceof RC2Key)) {
			throw new InvalidKeySpecException("wrong key type");
		}

		return new SecretKeySpec(key.getEncoded(), "RC2");
	}

	/**
	 * Translate an RC2 key object, whose provider may be unknown or potentially
	 * untrusted, into a corresponding key object of this key factory.
	 * Currently, only {@link RC2Key} is supported as source format.
	 * 
	 * @param key
	 *            the source key
	 * @return the translated key
	 * @throws InvalidKeyException
	 *             if the given key is not an instance of {@link RC2Key}
	 */
	public SecretKey translateKey(SecretKey key) throws InvalidKeyException {
		if (!(key instanceof RC2Key)) {
			throw new InvalidKeyException();
		}
		return key;
	}

}
