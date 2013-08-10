package de.flexiprovider.core.rsa;

import de.flexiprovider.api.exceptions.BadPaddingException;
import de.flexiprovider.api.exceptions.IllegalBlockSizeException;

/**
 * Implements the PKCS1v5 RSA as a cipher with unlimited length for plaintexts and ciphertexts.
 * First it truncates a big message to smaller messages that can be processed by a standard RSA encryption. 
 * This depends also on the key size. For example for a 1024 bits key only up to 117 (128-11) bytes can be en/decrypted. 
 * Upon an input of 304 bytes, first three submessages are created. The first one is 70 (304-2*117) bytes long and the other two 117.
 * Each message is encrypted with a normal PKCS1v5 RSA encryption. The ciphertext is 384 (3*128) bytes long. This is also truncated 
 * to three messages of 128 bytes which are also decrypted by a normal RSA operation.
 *  
 * @author Michael Gaber
 *
 */
public class UnlimitedLengthRSA extends RSA_PKCS1_v1_5 {

	// the name of the algorithm
	public static final String NAME = "UnlimitedLengthRSA";

	/**
	 * Decrypts this message of unlimited length. The length of the message however still needs to
	 * be a multiple of a normal RSA to-be-decrypted message.
	 * 
	 * @return the decrypted message.
	 */
	protected byte[] messageDecrypt(byte[] input)
			throws IllegalBlockSizeException, BadPaddingException {
		// if doable by simple RSA, do it this way
		if (input.length == cipherTextSize) {
			return super.messageDecrypt(input);
		}
		// else do it splitted
		byte[] rv = null;
		if (input.length % cipherTextSize != 0) {
			throw new IllegalBlockSizeException("not enough bytes of ciphertext");
		}
		int runs = input.length / cipherTextSize;
		
		for (int i = runs; i > 0; i--) {
			int splitter = i * cipherTextSize;
			if (i == runs) {
				byte[] tmp = new byte[cipherTextSize];
				System.arraycopy(input, splitter - cipherTextSize, tmp, 0, cipherTextSize);
				tmp = super.messageDecrypt(tmp);
				rv = new byte[(runs - 1) * maxPlainTextSize + tmp.length];
				System.arraycopy(tmp, 0, rv, rv.length - tmp.length, tmp.length);
			} else {
				byte[] tmp = new byte[cipherTextSize];
				System.arraycopy(input, splitter - cipherTextSize, tmp, 0, cipherTextSize);
				System.arraycopy(super.messageDecrypt(tmp), 0, rv, (i - 1) * maxPlainTextSize, maxPlainTextSize);
			}
		}
		return rv;
	}

	/**
	 * Encrypts this message of unlimited length. 
	 * 
	 * @return the ciphertext message.
	 */
	
	protected byte[] messageEncrypt(byte[] input) throws BadPaddingException {
		// if shorter than normal doable RSA simply do it.
		if (input.length <= maxPlainTextSize)
			return super.messageEncrypt(input);
		// else split it
		int remainder = input.length % maxPlainTextSize;
		int runs = input.length / maxPlainTextSize;
		byte[] rv = new byte[(runs + (remainder == 0 ? 0 : 1)) * cipherTextSize];

		if (remainder != 0) {
			byte[] tmp = new byte[remainder];
			System.arraycopy(input, input.length - remainder, tmp, 0, remainder);
			tmp = super.messageEncrypt(tmp);
			System.arraycopy(tmp, 0, rv, runs*cipherTextSize, cipherTextSize);
		}
		for (int i = runs; i > 0; i--) {
			int splitter = i * maxPlainTextSize;
			byte[] tmp = new byte[maxPlainTextSize];
			System.arraycopy(input, splitter - maxPlainTextSize, tmp, 0, maxPlainTextSize);
			tmp = super.messageEncrypt(tmp);
			System.arraycopy(tmp, 0, rv, (i - 1) * cipherTextSize, cipherTextSize);
		}
		return rv;
	}

	/**
	 * Return the name of the encrpytion algorithm.
	 * 
	 * @return the name of the encryption algorithm.
	 */
	public String getName() {
		return NAME;
	}

	/**
	 * Checks whether the plaintext or the ciphertext have correct sizes. While for plaintexts there are no restrictions, the ciphertext
	 * must be a multiple of a normal RSA to-be-decrypted message.
	 * 
	 */
	protected void checkLength(int inLength) throws IllegalBlockSizeException {
		if (inLength <= 0) {
			throw new IllegalBlockSizeException("Negative input length");
		}
		else if (opMode == DECRYPT_MODE && inLength % cipherTextSize != 0) {
			throw new IllegalBlockSizeException("Illegal ciphertext length (expected " + cipherTextSize
					+ " bytes, was " + inLength + " bytes).");
		}
	}
}
