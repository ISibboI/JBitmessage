/* Copyright 2000 Fraunhofer Gesellschaft
 * Leonrodstr. 54, 80636 Munich, Germany.
 * All rights reserved.
 *
 * You shall use this software only in accordance with
 * the terms of the license agreement you entered into
 * with Fraunhofer Gesellschaft.
 */
package javax.crypto.spec;

import java.security.spec.AlgorithmParameterSpec;

/**
 * 
 * @author Patric kabus
 * @version "$Id: IvParameterSpec.java,v 1.1.1.1 2001/05/15 11:59:09 krprvadm
 *          Exp $"
 */
public class IvParameterSpec implements AlgorithmParameterSpec {
	private byte[] iv_;

	public IvParameterSpec(byte[] iv) {
		this(iv, 0, iv.length);
	}

	public IvParameterSpec(byte[] iv, int offset, int len) {
		if (iv == null) {
			throw new NullPointerException("IV must not be null");
		}
		if (iv.length - offset < len) {
			throw new IllegalArgumentException(
					"iv buffer too small for given offset and length");
		}
		iv_ = new byte[len];

		System.arraycopy(iv, offset, iv_, 0, len);
	}

	public byte[] getIV() {
		return (byte[]) iv_.clone();
	}
}
