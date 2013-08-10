/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.pqc.ots.lm;

import java.util.Vector;

import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.math.IntegerFunctions;
import de.flexiprovider.common.math.polynomials.GFP32Polynomial;

/**
 * This class provides the specification of the parameters used by the
 * {@link LMOTSKeyPairGenerator}
 */
public class LMOTSParameterSpec implements AlgorithmParameterSpec {

	private int[] f;

	private int phi;

	private int degree;

	private int m;

	private int p;

	private LMOTSHash hFunction;

	// ****************************************************
	// JCA adapter methods
	// ****************************************************

	/**
	 * (EXAMPLE/TEST ONLY) Constructs an example Parameter spec using the bit
	 * length of the Encryption Key. This should be understood as a test or
	 * example parameter spec and not necessary one that is applicable for
	 * actual use.
	 * 
	 * @param keysize
	 *            the bit length of the key used for encrypting the message
	 */
	public LMOTSParameterSpec(int keysize) {
		phi = 1;

		f = new int[keysize];
		f[0] = 5;
		for (int i = keysize - 2; i > 0; i--) {
			f[i] = 0;
		}
		f[keysize - 1] = 1;

		degree = f.length - 1;
		m = IntegerFunctions.ceilLog(degree);
		p = IntegerFunctions.pow(degree * phi, 3);
	}

	/**
	 * Construct new LMOTS parameters from the given parameters.
	 * 
	 * @param f
	 *            irreducible polynomial specified on page 10 in the paper
	 * @param phi
	 *            this parameter depends on f and is described on page 7 in the
	 *            paper
	 */
	public LMOTSParameterSpec(int[] f, int phi) {
		this.f = f;
		this.phi = phi;

		degree = f.length - 1;
		m = IntegerFunctions.ceilLog(degree);
		p = IntegerFunctions.pow(degree * phi, 3);
	}

	/**
	 * @return returns the degree of f
	 */
	public int getDegree() {
		return degree;
	}

	/**
	 * @return returns the function f of this signature
	 */
	public int[] getF() {
		return f;
	}

	/**
	 * @return returns the hash function of this signature
	 */
	public LMOTSHash getHFunction() {
		return hFunction;
	}

	/**
	 * @return returns the m parameter of this signature
	 */
	public int getM() {
		return m;
	}

	/**
	 * @return returns the p parameter of this signature
	 */
	public int getP() {
		return p;
	}

	/**
	 * @return returns the phi parameter of f
	 */
	public int getPhi() {
		return phi;
	}

	/**
	 * @param a
	 *            a vector of {@link GFP32Polynomial} needed to instantiate a
	 *            hash function ({@link LMOTSHash})
	 */
	public void setHFunction(Vector a) {
		hFunction = new LMOTSHash(a);
	}

}
