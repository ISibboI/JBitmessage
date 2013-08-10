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

public class RC5ParameterSpec extends Object implements AlgorithmParameterSpec {
	private byte[] iv_;

	private int rounds_;

	private int wordSize_;

	private int version_;

	public RC5ParameterSpec(int version, int rounds, int wordSize) {
		version_ = version;
		rounds_ = rounds;
		wordSize_ = wordSize;
	}

	public RC5ParameterSpec(int version, int rounds, int wordSize, byte[] iv) {
		this(version, rounds, wordSize, iv, 0);
	}

	public RC5ParameterSpec(int version, int rounds, int wordSize, byte[] iv,
			int offset) {
		int length;

		if (iv == null) {
			throw new NullPointerException("iv");
		}
		length = 2 * (wordSize / 8);
		if (iv.length < offset + length) {
			throw new IllegalArgumentException(
					"iv buffer too small for given length and offset");
		}
		iv_ = new byte[length];
		System.arraycopy(iv, offset, iv_, 0, length);
		version_ = version;
		rounds_ = rounds;
		wordSize_ = wordSize;
	}

	public int getVersion() {
		return version_;
	}

	public int getRounds() {
		return rounds_;
	}

	public int getWordSize() {
		return wordSize_;
	}

	public byte[] getIV() {
		return (byte[]) iv_.clone();
	}
}
