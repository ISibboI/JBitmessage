/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.ec.keys;

import de.flexiprovider.api.keys.KeySpec;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.ec.parameters.CurveParams;

/**
 * This class specifies an EC private key with its associated parameters.
 * 
 * @see de.flexiprovider.api.keys.Key
 * @see de.flexiprovider.api.keys.KeySpec
 * @see de.flexiprovider.ec.keys.ECPublicKeySpec
 * @see de.flexiprovider.common.math.ellipticcurves.Point
 * @see CurveParams
 * 
 * @author Birgit Henhapl
 * @author Michele Boivin
 */
public final class ECPrivateKeySpec implements KeySpec {

    // //////////////////////////////////////////////////////////////
    // fields //
    // //////////////////////////////////////////////////////////////

    /**
     * Holds the ECParameterSpec.
     */
    private CurveParams mParams;

    /**
     * Holds s, 1 < s < r, public key. r is order of G, generator of the
     * subgroup.
     * 
     * @serial
     */
    private FlexiBigInt mS;

    // //////////////////////////////////////////////////////////////
    // constructor //
    // //////////////////////////////////////////////////////////////

    /**
     * Constructs a new private key specification. The parameters are the
     * private key <tt>s</tt> and an ecdomain parameters specification
     * <tt>params</tt> (see <a href =
     * ../..spec.ECParameterSpec.html>ECParameterSpec</a>).
     * 
     * @param s
     *                private key represented by a FlexiBigInt
     * @param params
     *                an ecdomain parameters specification
     */
    public ECPrivateKeySpec(FlexiBigInt s, CurveParams params) {
	mParams = params;
	mS = s;
    }

    // //////////////////////////////////////////////////////////////
    // access //
    // //////////////////////////////////////////////////////////////

    /**
     * Returns the private key s. 1 < s < r, r is the order of point G, member
     * of the ECDomain Parameters.
     * 
     * @return the private key s
     */
    public FlexiBigInt getS() {
	return mS;
    }

    /**
     * Returns the ECDomain Parameters params.
     * 
     * @return the parameters params
     */
    public CurveParams getParams() {
	return mParams;
    }

}
