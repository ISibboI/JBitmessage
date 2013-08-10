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


/**
 * This class specifies an SSVElGamal private key.
 * 
 * @see SSVElGamalKeyFactory
 * 
 * @author Thomas Wahrenbruch
 * @author Roberto Samarone dos Santos Araújo
 * 
 */
public class SSVElGamalPrivateKeySpec implements KeySpec {

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
	 * The public value <tt>A = g<sup>a</sup> mod modulusp</tt>.
	 */
	private FlexiBigInt publicA;

	/**
	 * The private value <tt>a</tt>
	 */
	private FlexiBigInt a;

	/**
	 * The constructor.
	 * 
	 * @param modulusp
	 *            - the prime modulus which specifies the group
	 * @param modulusq
	 *            - the prime modulus which specifies the subgroup
	 * @param generator
	 *            - a generator of the group
	 * @param publicA
	 *            - the public value <tt>A = g<sup>a</sup> mod modulus</tt>
	 * @param a
	 *            - the private value <tt>a</tt>
	 */
	public SSVElGamalPrivateKeySpec(FlexiBigInt modulusp, FlexiBigInt modulusq,
			FlexiBigInt generator, FlexiBigInt publicA, FlexiBigInt a) {
		this.modulusP = modulusp;
		this.modulusQ = modulusq;
		this.generator = generator;
		this.publicA = publicA;
		this.a = a;
	}

	/**
	 * @return the prime modulus p
	 */
	public final FlexiBigInt getModulusP() {
		return modulusP;
	}

	/**
	 * @return the prime modulus q
	 */
	public final FlexiBigInt getModulusQ() {
		return modulusQ;
	}

	/**
	 * @return the generator
	 */
	public final FlexiBigInt getGenerator() {
		return generator;
	}

	/**
	 * @return the public value <tt>A = g<sup>a</sup> mod modulusp</tt>
	 */
	public final FlexiBigInt getPublicA() {
		return publicA;
	}

	/**
	 * @return the private value <tt>a</tt>
	 */
	public final FlexiBigInt getA() {
		return a;
	}

}
