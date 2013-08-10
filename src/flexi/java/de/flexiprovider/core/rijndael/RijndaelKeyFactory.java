/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.rijndael;

import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.exceptions.InvalidKeySpecException;
import de.flexiprovider.api.keys.KeySpec;
import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.api.keys.SecretKeyFactory;
import de.flexiprovider.api.keys.SecretKeySpec;
import de.flexiprovider.core.rijndael.Rijndael.AES;

/**
 * This class represents a factory for secret keys. This class is used to
 * convert Rijndael keys into a format usable by the CDC provider. The supported
 * KeySpec class is RijndaelKeySpec.
 * <p>
 * This class should not be instantiated directly, instead use the
 * {@link SecretKeyFactory} interface.
 * 
 * @see SecretKeyFactory
 * @author Katja Rauch
 */
public final class RijndaelKeyFactory extends SecretKeyFactory {

	/**
	 * Generate a Rijndael key object from the provided key specification. The
	 * key specification has to be an instance of {@link SecretKeySpec} of type
	 * "Rijndael" or of type "AES".
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
			String algorithm = secKeySpec.getAlgorithm();
			if (algorithm.equals(Rijndael.ALG_NAME)
					|| algorithm.startsWith(AES.ALG_NAME)
					|| algorithm.startsWith(AES.OID)) {
				return new RijndaelKey(secKeySpec.getEncoded());
			}
		}

		throw new InvalidKeySpecException("Unsupported key specification type.");
	}

	/**
	 * Return a key specification of the given key object in the requested
	 * format. The format has to be equal to or a superclass of
	 * {@link SecretKeySpec}. The key has to be an instance of
	 * {@link RijndaelKey}.
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
	 *             given key has an unrecognised format).
	 */
	public KeySpec getKeySpec(SecretKey key, Class keySpec)
			throws InvalidKeySpecException {

		if ((keySpec == null) || !keySpec.isAssignableFrom(SecretKeySpec.class)) {
			throw new InvalidKeySpecException("wrong spec type");
		}
		if ((key == null) || !(key instanceof RijndaelKey)) {
			throw new InvalidKeySpecException("wrong key type");
		}

		return new SecretKeySpec(key.getEncoded(), "Rijndael");
	}

	/**
	 * Translates a Rijndael key object, whose provider may be unknown or
	 * potentially untrusted, into a corresponding key object of this key
	 * factory. Not currently implemented.
	 * 
	 * @param key
	 *            the key whose provider is unknown or untrusted
	 * @return the translated key
	 * @throws InvalidKeyException
	 *             if the given key cannot be processed by this key factory.
	 */
	public SecretKey translateKey(SecretKey key) throws InvalidKeyException {
		throw new InvalidKeyException("not implemented");
	}

}
