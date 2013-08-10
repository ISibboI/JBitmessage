/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.elgamal;

import de.flexiprovider.api.keys.KeySpec;
import de.flexiprovider.common.math.FlexiBigInt;

// import asn1.*;

/**
 * This class specifies an ElGamal public key.
 * 
 * @see ElGamalKeyFactory
 * @author Thomas Wahrenbruch
 */
public class ElGamalPublicKeySpec implements KeySpec {

    /**
     * The prime modulus which specifies the group
     */
    private FlexiBigInt modulus;

    /**
     * A generator of <tt>(Zp/Z)*</tt>
     */
    private FlexiBigInt generator;

    /**
     * The public value <tt>A = g<sup>a</sup> mod modulus</tt>.
     */
    private FlexiBigInt publicA;

    /**
     * The constructor.
     * 
     * @param modulus -
     *                the prime modulus which specifies the group
     * @param generator -
     *                a generator of the group
     * @param publicA -
     *                the public value <tt>A = g<sup>a</sup> mod modulus</tt>
     */
    public ElGamalPublicKeySpec(FlexiBigInt modulus, FlexiBigInt generator,
	    FlexiBigInt publicA) {
	this.modulus = modulus;
	this.generator = generator;
	this.publicA = publicA;
    }

    /**
     * @return the prime modulus
     */
    public FlexiBigInt getModulus() {
	return modulus;
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
