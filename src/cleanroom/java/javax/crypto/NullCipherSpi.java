/* Copyright 2000 Fraunhofer Gesellschaft
 * Leonrodstr. 54, 80636 Munich, Germany.
 * All rights reserved.
 *
 * You shall use this software only in accordance with
 * the terms of the license agreement you entered into
 * with Fraunhofer Gesellschaft.
 */
package javax.crypto;

import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class NullCipherSpi extends CipherSpi {
    public NullCipherSpi() {
	super();
    }

    protected void engineSetMode(String mode) {
    }

    protected void engineSetPadding(String padding) {
    }

    public int engineGetBlockSize() {
	return 1;
    }

    public int engineGetOutputSize(int inputLen) throws IllegalStateException {
	return inputLen;
    }

    public byte[] engineGetIV() {
	return null;
    }

    public AlgorithmParameters engineGetParameters() {
	return null;
    }

    protected void engineInit(int opmode, Key key, SecureRandom random) {
    }

    public void engineInit(int opmode, Key key, AlgorithmParameterSpec params,
	    SecureRandom random) {
    }

    protected void engineInit(int opmode, Key key, AlgorithmParameters params,
	    SecureRandom random) {
    }

    public final byte[] engineUpdate(byte[] input, int inputOffset, int inputLen)
	    throws IllegalStateException {
	byte[] buf;

	checkInputParameters(input, inputOffset, inputLen);
	buf = new byte[inputLen];
	System.arraycopy(input, inputOffset, buf, 0, inputLen);
	return buf;
    }

    public final int engineUpdate(byte[] input, int inputOffset, int inputLen,
	    byte[] output, int outputOffset) throws IllegalStateException,
	    ShortBufferException {
	checkInputParameters(input, inputOffset, inputLen);
	checkOutputParameters(output, outputOffset);
	if (output.length < (outputOffset + inputLen)) {
	    throw new ShortBufferException(
		    "buffer too small: cannot place result at given offset");
	}
	System.arraycopy(input, inputOffset, output, outputOffset, inputLen);
	return inputLen;
    }

    public final byte[] engineDoFinal(byte[] input, int inputOffset,
	    int inputLen) throws IllegalStateException {
	return engineUpdate(input, inputOffset, inputLen);
    }

    public final int engineDoFinal(byte[] input, int inputOffset, int inputLen,
	    byte[] output, int outputOffset) throws IllegalStateException,
	    ShortBufferException {
	return engineUpdate(input, inputOffset, inputLen, output, outputOffset);
    }

    private void checkInputParameters(byte[] input, int inputOffset,
	    int inputLen) {
	if (input == null) {
	    throw new NullPointerException("input");
	}
	if (inputOffset < 0) {
	    throw new IllegalArgumentException("input offset is <0");
	}
	if (inputLen < 0) {
	    throw new IllegalArgumentException("input length < 0");
	}
	if (inputLen > (input.length - inputOffset)) {
	    throw new ArrayIndexOutOfBoundsException(
		    "input buffer too small for given length and offset");
	}
    }

    private void checkOutputParameters(byte[] output, int outputOffset) {
	if (output == null) {
	    throw new NullPointerException("output");
	}
	if (outputOffset < 0) {
	    throw new IllegalArgumentException("output offset is <0");
	}
	if (output.length <= outputOffset) {
	    throw new ArrayIndexOutOfBoundsException(
		    "output buffer too small for given offset");
	}
    }
}
