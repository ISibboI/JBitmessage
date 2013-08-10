/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.desede;

import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.exceptions.InvalidKeySpecException;
import de.flexiprovider.api.keys.KeySpec;
import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.api.keys.SecretKeySpec;

/**
 * This class represents a factory for secret keys. This class is used to
 * convert DESede keys into a format usable by the FlexiProvider. Currently this
 * class can only convert from a KeySpec into a Key. The supported KeySpec class
 * is DESedeKeySpec.
 * <p>
 * This class should not be instantiated directly, instead use the
 * java.security.KeyFactory interface.
 * 
 * @author Norbert Trummel , Sylvain Franke
 */
public class DESedeKeyFactory extends
		de.flexiprovider.core.desede.interfaces.DESedeKeyFactory {

	/**
	 * Generates a DESede SecretKey object from the provided key specification
	 * (key material).
	 * 
	 * @param keySpec
	 *            the specification (key material) of the secret key
	 * @return the secret key
	 * @throws InvalidKeySpecException
	 *             if the given key specification is inappropriate for this
	 *             secret key factory to produce a secret key.
	 */
	public final SecretKey generateSecret(KeySpec keySpec)
			throws InvalidKeySpecException {

		if (keySpec == null) {
			throw new InvalidKeySpecException("Key specification is null.");
		}

		if (keySpec instanceof DESedeKeySpec) {
			return new DESedeKey(((DESedeKeySpec) keySpec).getKey());
		}

		if (keySpec instanceof SecretKeySpec) {
			SecretKeySpec secKeySpec = (SecretKeySpec) keySpec;
			String algName = secKeySpec.getAlgorithm();
			if (algName.equals(DESede.ALG_NAME)
					|| algName.equals(DESede.DESede_CBC.OID)) {
				return new DESedeKey(secKeySpec.getEncoded());
			}
		}

		throw new InvalidKeySpecException("Unsupported key specification type.");
	}

	/**
	 * Return a specification (key material) of the given key object in the
	 * requested format.
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
	public final KeySpec getKeySpec(SecretKey key, Class keySpec)
			throws InvalidKeySpecException {

		if (keySpec == null || !keySpec.isAssignableFrom(DESedeKeySpec.class)) {
			throw new InvalidKeySpecException("unsupported type");
		}
		if (key == null) {
			throw new InvalidKeySpecException("key is null");
		}

		KeySpec desKeySpec;
		try {
			desKeySpec = new DESedeKeySpec(key.getEncoded());
		} catch (InvalidKeyException e) {
			throw new InvalidKeySpecException(e.getMessage());
		}

		return desKeySpec;
	}

	/**
	 * Translates a DESede key object, whose provider may be unknown or
	 * potentially untrusted, into a corresponding key object of this key
	 * factory. Not currently implemented.
	 * 
	 * @param key
	 *            the key whose provider is unknown or untrusted
	 * @return the translated key
	 * @throws InvalidKeyException
	 *             if the given key cannot be processed by this key factory.
	 */
	public final SecretKey translateKey(SecretKey key)
			throws InvalidKeyException {
		throw new InvalidKeyException("not implemented");
	}

}
