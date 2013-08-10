/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.elgamal.semanticallysecure;

import de.flexiprovider.api.keys.KeySpec;
import de.flexiprovider.common.math.FlexiBigInt;

// import asn1.*;

/**
 * This class specifies an ElGamal public key.
 * 
 * @see SSVElGamalKeyFactory
 * 
 * @author Thomas Wahrenbruch
 * @author Roberto Samarone dos Santos Araújo
 * 
 */
public class SSVElGamalPublicKeySpec implements KeySpec {

	/**
	 * The prime modulus which specifies the group
	 */
	private FlexiBigInt modulusP;

	/**
	 * The prime modulus which specifies the subgroup
	 */
	private FlexiBigInt modulusQ;

	/**
	 * A generator of <tt>(Zp/Z)*</tt>
	 */
	private FlexiBigInt generator;

	/**
	 * The public value <tt>A = g<sup>a</sup> mod modulusP</tt>.
	 */
	private FlexiBigInt publicA;

	/**
	 * The constructor.
	 * 
	 * @param modulusP
	 *            the prime modulus p which specifies the group
	 * @param modulusQ
	 *            the prime modulus q which specifies the subgroup
	 * @param generator
	 *            a generator of the group
	 * @param publicA
	 *            the public value <tt>A = g<sup>a</sup> mod modulus</tt>
	 */
	public SSVElGamalPublicKeySpec(FlexiBigInt modulusP, FlexiBigInt modulusQ,
			FlexiBigInt generator, FlexiBigInt publicA) {
		this.modulusP = modulusP;
		this.modulusQ = modulusQ;
		this.generator = generator;
		this.publicA = publicA;
	}

	/**
	 * @return the prime modulus p
	 */
	public FlexiBigInt getModulusP() {
		return modulusP;
	}

	/**
	 * @return the prime modulus q
	 */
	public FlexiBigInt getModulusQ() {
		return modulusQ;
	}

	/**
	 * @return the generator
	 */
	public FlexiBigInt getGenerator() {
		return generator;
	}

	/**
	 * @return the public value <tt>A = g<sup>a</sup> mod modulus</tt>
	 */
	public FlexiBigInt getPublicA() {
		return publicA;
	}

}
