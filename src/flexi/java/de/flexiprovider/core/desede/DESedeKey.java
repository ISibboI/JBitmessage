/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.desede;

import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.common.util.ByteUtils;

/**
 * DESedeKey is used to store a symmetric Key for DESede Encryption/Decryption.
 * 
 * @author Norbert Trummel , Sylvain Franke
 */
public class DESedeKey implements SecretKey {

	/**
	 * This array is used to store the key data
	 */
	private byte[] keyBytes;

	/**
	 * Construct a new key from the given key bytes.
	 * 
	 * @param keyBytes
	 *            the key bytes
	 */
	protected DESedeKey(byte[] keyBytes) {
		this.keyBytes = ByteUtils.clone(keyBytes);
	}

	/**
	 * Return the name of the algorithm the key is used for.
	 * 
	 * @return {@link DESede.algName}
	 */
	public String getAlgorithm() {
		return DESede.ALG_NAME;
	}

	/**
	 * @return the encoded key (a copy of the key bytes)
	 */
	public byte[] getEncoded() {
		return ByteUtils.clone(keyBytes);
	}

	/**
	 * Return the encoding format of the key.
	 * 
	 * @return "RAW"
	 */
	public String getFormat() {
		return "RAW";
	}

	/**
	 * Compare the given object with this key
	 * 
	 * @param other
	 *            other object
	 * @return the result of the comparison
	 */
	public boolean equals(Object other) {
		if (other == null || !(other instanceof DESedeKey)) {
			return false;
		}
		DESedeKey otherKey = (DESedeKey) other;
		return ByteUtils.equals(keyBytes, otherKey.keyBytes);
	}

	/**
	 * @return the hash code of this key
	 */
	public int hashCode() {
		int result = 1;
		for (int i = 0; i < keyBytes.length; i++) {
			result = 31 * result + keyBytes[i];
		}

		return result;
	}

}
