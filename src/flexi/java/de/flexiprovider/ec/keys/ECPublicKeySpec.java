/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.ec.keys;

import de.flexiprovider.api.exceptions.InvalidKeySpecException;
import de.flexiprovider.api.exceptions.InvalidParameterException;
import de.flexiprovider.api.exceptions.InvalidParameterSpecException;
import de.flexiprovider.api.keys.KeySpec;
import de.flexiprovider.common.exceptions.InvalidFormatException;
import de.flexiprovider.common.exceptions.InvalidPointException;
import de.flexiprovider.common.math.ellipticcurves.Point;
import de.flexiprovider.common.util.ByteUtils;
import de.flexiprovider.ec.parameters.CurveParams;

/**
 * This class specifies a EC public key with its associated parameters.
 * 
 * @see KeySpec
 * @see de.flexiprovider.api.keys.KeyFactory
 * @see de.flexiprovider.pki.X509EncodedKeySpec
 * @see de.flexiprovider.ec.keys.ECPrivateKeySpec
 * @see de.flexiprovider.common.math.ellipticcurves.Point
 * @see CurveParams
 * 
 * @author Birgit Henhapl
 * @author Michele Boivin
 */
public final class ECPublicKeySpec implements KeySpec {

    // //////////////////////////////////////////////////////////////
    // fields //
    // //////////////////////////////////////////////////////////////

    /**
     * holds W := s * G, 1 < s < r, public key
     * 
     * @serial
     */
    private Point mW;

    /**
     * holds the encoded point W in case no parameters were presented in ordere
     * to generate the point object.
     */
    private byte[] mEncodedW;

    /**
     * holds the parameters
     * 
     * @serial
     */
    private CurveParams mParams;

    // //////////////////////////////////////////////////////////////
    // constructor //
    // //////////////////////////////////////////////////////////////

    /**
     * Constructs a new public key specification. The parameters are the public
     * key <tt>W</tt> and an EC domain parameters specification
     * <tt>params</tt> (see <a href =
     * ../..spec.ECParameterSpec.html>ECParameterSpec</a>).
     * 
     * @param W
     *                public key represented by a Point
     * @param params
     *                ECParameterSpec, characteristic of underlying field
     * @throws InvalidParameterException
     *                 if <tt>params == null</tt> or <tt>params</tt> does
     *                 not match parameters specified by <tt>W</tt>.
     */
    public ECPublicKeySpec(Point W, CurveParams params)
	    throws InvalidParameterException {
	if (params == null) {
	    throw new InvalidParameterException(
		    "EC domain parameters must not be null");
	}
	// TODO: Test if params match curve encoded in point
	mW = W;
	mParams = params;
    }

    /**
     * Generate an EC key specification based on an encoded point and optionally
     * the parameters of the curve. If curve parameters are presented, the point
     * is decoded (which may lead to the Exceptions named below). Otherwise, the
     * point is internally represented as byte array.
     * 
     * Uncompressed encoding must be chosen for the point.
     * 
     * @param encodedW
     *                the point in its uncompressed encoding
     * @param params
     *                EC domain parameters
     * @throws InvalidParameterSpecException
     *                 if the point cannot be decoded with the given parameters.
     */
    public ECPublicKeySpec(byte[] encodedW, CurveParams params)
	    throws InvalidParameterSpecException {
	mEncodedW = ByteUtils.clone(encodedW);
	if (params != null) {
	    setParams(params);
	}
    }

    /**
     * Copy constructor.
     * 
     * @param other
     *                another ECPublicKeySpec
     */
    public ECPublicKeySpec(ECPublicKeySpec other) {
	if (other.mW != null) {
	    mW = (Point) other.mW.clone();
	}

	if (other.mEncodedW != null) {
	    mEncodedW = ByteUtils.clone(other.mEncodedW);
	}

	mParams = other.mParams;
    }

    // //////////////////////////////////////////////////////////////
    // access //
    // //////////////////////////////////////////////////////////////

    /**
     * Returns the public key W. W = sG, s is private key, G generator of the
     * subgroup.
     * 
     * @return the public key W
     * @throws InvalidKeySpecException
     *                 if no EC domain parameters have been defined for this
     *                 public key yet.
     * @see de.flexiprovider.common.math.ellipticcurves.Point
     */
    public Point getW() throws InvalidKeySpecException {
	if (mW == null) {
	    throw new InvalidKeySpecException(
		    "No EC domain parameters defined for the public point");
	}
	return mW;
    }

    /**
     * @return the public key in its uncompressed encoding
     */
    public byte[] getEncodedW() {
	if (mEncodedW != null) {
	    return mEncodedW;
	}

	return mW.EC2OSP(Point.ENCODING_TYPE_UNCOMPRESSED);
    }

    /**
     * @return the EC domain parameters
     */
    public CurveParams getParams() {
	return mParams;
    }

    /**
     * Set the EC domain parameters for this public key.
     * 
     * @param params
     *                the domain parameters
     * @throws InvalidParameterSpecException
     *                 if the domain parameters are already set and
     *                 <tt>params</tt> is not equal to the set parameters or
     *                 if the encoded point cannot be decoded with the given
     *                 parameters.
     */
    public void setParams(CurveParams params)
	    throws InvalidParameterSpecException {

	if (params == null) { // case 1: deleting EC domain parameters
	    // public point is already in the respective format
	    if (mEncodedW != null) {
		return;
	    }

	    // public point has to be encoded first
	    mEncodedW = mW.EC2OSP(Point.ENCODING_TYPE_UNCOMPRESSED);
	    mW = null;
	} else { // case 2: defining EC domain parameters
	    if (mParams == null) {
		try {
		    mW = Point.OS2ECP(mEncodedW, params);
		    mParams = params;
		    mEncodedW = null;
		} catch (InvalidPointException ipe) {
		    throw new InvalidParameterException(
			    "Unable to compute point object from encoded point "
				    + "and given EC domain parameters "
				    + "(caught InvalidPointException: "
				    + ipe.getMessage() + ").");
		} catch (InvalidFormatException ife) {
		    throw new InvalidParameterException(
			    "Unable to compute point object from encoded point "
				    + "and given EC domain parameters "
				    + "(caught InvalidFormatException: "
				    + ife.getMessage() + ").");
		}
	    } else {
		// in this case nothing needs to be done
		if (mParams.equals(params)) {
		    return;
		}

		throw new InvalidParameterException(
			"Illegally tried to change existing curve parameters.");
	    }
	}

    }

}
