package de.flexiprovider.core.pbe;

import de.flexiprovider.api.parameters.AlgorithmParameterSpec;

/**
 * This class provides a specification for the parameters used by the PBKDF1 key
 * derivation function specified in <a
 * href="http://www.rsa.com/rsalabs/node.asp?id=2127">PKCS #5 v2.0</a>.
 */
public class PBEParameterSpec extends javax.crypto.spec.PBEParameterSpec
		implements AlgorithmParameterSpec {

	private static final byte[] DEFAULT_SALT = new byte[0];

	private static final int DEFAULT_ITERATION_COUNT = 1000;

	// ****************************************************
	// JCA adapter methods
	// ****************************************************

	/**
	 * Construct new PBKDF1 parameters from of the given
	 * {@link javax.crypto.spec.PBEParameterSpec}.
	 * 
	 * @param paramSpec
	 *            the {@link javax.crypto.spec.PBEParameterSpec}
	 */
	public PBEParameterSpec(javax.crypto.spec.PBEParameterSpec paramSpec) {
		this(paramSpec.getSalt(), paramSpec.getIterationCount());
	}

	// ****************************************************
	// FlexiAPI methods
	// ****************************************************

	/**
	 * Construct the PBE default parameters.
	 */
	public PBEParameterSpec() {
		this(DEFAULT_SALT, DEFAULT_ITERATION_COUNT);
	}

	/**
	 * Construct new PBE parameters using the given salt and iteration count.
	 * 
	 * @param salt
	 *            the salt
	 * @param iterationCount
	 *            the iteration count
	 */
	public PBEParameterSpec(byte[] salt, int iterationCount) {
		super(salt, iterationCount);
	}

}
