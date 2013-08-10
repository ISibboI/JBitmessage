/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */
package de.flexiprovider.ec;

import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.common.exceptions.InvalidPointException;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.math.ellipticcurves.EllipticCurveGFP;
import de.flexiprovider.common.math.ellipticcurves.PointGFP;
import de.flexiprovider.common.math.ellipticcurves.ScalarMult;
import de.flexiprovider.common.math.finitefields.GFPElement;
import de.flexiprovider.common.util.SeedGenerator;

/**
 * This class implements a pseudorandom number generator as proposed by Kaliski.
 * Its security bases on the elliptic curve discrete logarithm problem. For
 * details, we refer to the ICICS 2002 paper of H. Baier.
 * 
 * The curve parameters are stored in a file named 'curve_parameters'. This file
 * has to be stored in the same directory as the Java-class containing the
 * main(...)-method . The validity of the parameters is not checked!!! Thus the
 * user is responsible for a good choice.
 * 
 * @author Harald Baier
 * @see EllipticCurveGFP
 */
public class ECPRNG extends SecureRandom {

    // parameters used by the PRNG
    private static final String p = "965627713414686037773998887356363665495489701319";
    private static final String r = "965627713414686037773998839797242751054848709919";
    private static final String a = "965627713414686037773998887356363665495489701316";
    private static final String b = "69258789294063637963571905734367242074831358211";
    private static final String gx = "180154915808782548921909613234120456530839054533";
    private static final String gy = "322027385971935282160204922182313022993137363211";
    private static final String gamma = "412034918207550707882137137021287579344082387488";
    private static final String rtw = "965627713414686037773998934915484579936130692721";
    private static final String atw = "965627713414686037773998887356363665495489701316";
    private static final String btw = "896368924120622399810426981621996423420658343108";
    private static final String gxtw = "366500700833382456097277943560492718018620012876";
    private static final String gytw = "386244879790635939190694479506736774122111430939";

    private SeedGenerator seedGenerator;

    // to store if ECPRNG is seeded
    private boolean mIsSeeded = false;

    private byte mCurrentByte;

    private int mSeedLength;

    // characteristic p of finite prime field
    private FlexiBigInt mP;

    // = ( mP - 1 )/2
    private FlexiBigInt mP_minus_1_half;

    // quadratic non-residue modulo mP for twisted curves
    private FlexiBigInt mGamma;

    // inverse of mGamma mod mP
    private FlexiBigInt mGammaInverse;

    // elliptic curve of prime order
    private EllipticCurveGFP mE;

    // twist of mE over \F_p
    private EllipticCurveGFP mE_tw;

    // the base point mG on mE of order mR
    private PointGFP mG;

    // array of multiples of mG
    private PointGFP[] mGArray;

    // prime order of mG in E(\F_p)
    private FlexiBigInt mR;

    // = ( mR - 1 )/2
    private FlexiBigInt mR_minus_1_half;

    private int bitLengthR;

    // base point in E_tw(\F_p)
    private PointGFP mG_tw;

    // array of multiples of mG_tw
    private PointGFP[] mG_twArray;

    // prime order of mG_tw in E_tw(\F_p)
    private FlexiBigInt mR_tw;

    // = ( mR_tw - 1 )/2
    private FlexiBigInt mR_tw_minus_1_half;

    private int bitLengthR_tw;

    // the current multiple of mG
    private PointGFP mPoint;

    // the (affine) x-coordinate of mPoint
    private FlexiBigInt mX;

    // the (affine) y-coordinate of mPoint
    private FlexiBigInt mY;

    // the value s of the paper
    private FlexiBigInt mS;

    // the value of s - r
    private FlexiBigInt mS_minus_mR;

    // a temporary variable
    private FlexiBigInt tmp;

    // variables for computing the current byte

    // the local byte
    private byte mLocalByte;

    // the bitmask to manipulate mLocalByte
    private byte mBitmask;

    /**
     * Constructor.
     * 
     * @throws InvalidPointException
     *                 should not happen with the default parameters.
     */
    public ECPRNG() throws InvalidPointException {

	// generate the seed generator object
	seedGenerator = new SeedGenerator();

	// initialize the prime field
	mP = new FlexiBigInt(p);

	// initialize the order r of G
	mR = new FlexiBigInt(r);

	// initialize the elliptic curve
	mE = new EllipticCurveGFP(new GFPElement(new FlexiBigInt(a), mP),
		new GFPElement(new FlexiBigInt(b), mP), mP);

	// initialize the base point G on E
	mG = new PointGFP(new GFPElement(new FlexiBigInt(gx), mP),
		new GFPElement(new FlexiBigInt(gy), mP), mE);

	// initialize the quadratic non-residue mGamma
	mGamma = new FlexiBigInt(gamma);

	// initialize the order r^tw of G^tw
	mR_tw = new FlexiBigInt(rtw);

	// initialize the elliptic curve E^tw
	mE_tw = new EllipticCurveGFP(new GFPElement(new FlexiBigInt(atw), mP),
		new GFPElement(new FlexiBigInt(btw), mP), mP);

	// initialize the base point G^tw on E^tw
	mG_tw = new PointGFP(new GFPElement(new FlexiBigInt(gxtw), mP),
		new GFPElement(new FlexiBigInt(gytw), mP), mE_tw);

	// compute mGammaInverse
	mGammaInverse = mGamma.modInverse(mP);

	// compute bitlengths of mR and mR_tw
	bitLengthR = mR.bitLength();
	bitLengthR_tw = mR_tw.bitLength();

	// compute (mP - 1)/2
	mP_minus_1_half = mP.subtract(FlexiBigInt.ONE);
	mP_minus_1_half = mP_minus_1_half.shiftRight(1);

	// compute (mR - 1)/2
	mR_minus_1_half = mR.subtract(FlexiBigInt.ONE);
	mR_minus_1_half = mR_minus_1_half.shiftRight(1);

	// compute (mR_tw - 1)/2
	mR_tw_minus_1_half = mR_tw.subtract(FlexiBigInt.ONE);
	mR_tw_minus_1_half = mR_tw_minus_1_half.shiftRight(1);

	// compute the length of the seed in bytes: bitlenghtR + 1 bits
	mSeedLength = (bitLengthR + 1) >> 3;

	// initialize mGArray with multiples of mG
	mPoint = new PointGFP(mG);
	mGArray = new PointGFP[bitLengthR];
	for (int kk = 0; kk < bitLengthR; kk++) {
	    mGArray[kk] = new PointGFP(mPoint);
	    mPoint.multiplyThisBy2();
	}

	mPoint = new PointGFP(mG_tw);
	mG_twArray = new PointGFP[bitLengthR_tw];
	for (int kk = 0; kk < bitLengthR_tw; kk++) {
	    mG_twArray[kk] = new PointGFP(mPoint);
	    mPoint.multiplyThisBy2();
	}
    } // end of constructor ECPRNG()

    /**
     * Generate a seed of the given length.
     * 
     * @param numBytes -
     *                the intended number of seed bytes
     * @return the seed as array of bytes
     */
    public byte[] generateSeed(int numBytes) {
	if (numBytes <= 0) {
	    return new byte[0];
	}
	java.security.SecureRandom sr = new java.security.SecureRandom();
	return sr.generateSeed(numBytes);
//	return this.generateSeed(numBytes);
    }

    /**
     * Sets the seed to the given argument.
     * 
     * @param seed -
     *                the seed
     */
    public void setSeed(byte[] seed) {
	initializeS(seed);
	mIsSeeded = true;
    }

    /**
     * Computes the required random bytes.
     * 
     * @param randomBytes -
     *                the output array
     */
    static long counter = 0;
    public void nextBytes(byte[] randomBytes) {
	
	counter++;
	int length = randomBytes.length;

	if (length == 0) {
	    return;
	}

	// set the seed
	if (!mIsSeeded) {
	    initializeS(generateSeed(mSeedLength));
	}

	for (int i = 0; i < length; i++) {
	    randomBytes[i] = phi();
	}

	// to ensure that a new seed is set before computing the next bytes
	if(counter%5000 == 0){
	    mIsSeeded = false;
	}
    } // end of engineNextBytes

    // the function initializeS() initializes S using the current Seed
    private void initializeS(byte[] seed) {
	mS = new FlexiBigInt(seed);

	// set tmp = 2*mP + 2
	tmp = new FlexiBigInt(mP.toString());
	tmp.shiftLeft(1);
	tmp = tmp.add(FlexiBigInt.ONE);
	tmp = tmp.add(FlexiBigInt.ONE);

	// if mS is negative, set it to its absolute value
	if (mS.compareTo(FlexiBigInt.ZERO) == -1) {
	    mS = mS.negate();
	}

	// if mS is not lower than 2mP+2, set it to the remainder
	if (mS.compareTo(tmp) != -1) {
	    mS = mS.remainder(tmp);
	}
    }

    // the function computeB() computes the byte B corresponding
    // to the current state mS as explained in the paper
    private byte computeB(FlexiBigInt s, FlexiBigInt r,
	    FlexiBigInt r_minus_1_half) {

	// initialize tmp with the current state mS = s
	tmp = new FlexiBigInt(s.toString());
	// mLocalByte stores the result; initialized with 0
	mLocalByte = 0;
	// mBitmask stores the current bit to set
	mBitmask = 1;

	for (int i = 0; i < 8; i++) {
	    // set the current bit
	    if ((tmp.compareTo(r_minus_1_half)) == 1) {
		mLocalByte |= mBitmask;
	    }

	    // update tmp: tmp <-- 2*tmp mod r
	    tmp = tmp.shiftLeft(1);
	    tmp = tmp.remainder(r);
	    // update mBitmask: mBitmask <-- 2*mBitmask
	    mBitmask <<= 1;
	} // end of for-loop

	return mLocalByte;
    } // end of private method computeB

    // the function phi() is explained in the paper
    private byte phi() {
	if (mS.equals(FlexiBigInt.ZERO)) {

	    // the current byte is equal to 0
	    mCurrentByte = 0;

	    // The point mPoint is equal to O in E(\F_p)
	    // The updated mS is equal to 2mP
	    mS = mP.shiftLeft(1); // mS = 2*mP

	    return mCurrentByte;
	}

	// mS is positive and smaller than mR
	if ((mS.compareTo(mR)) == -1) {
	    // compute the current byte
	    mCurrentByte = computeB(mS, mR, mR_minus_1_half);

	    // set mPoint <-- mS * mG
	    mPoint = (PointGFP) ScalarMult.eval_SquareMultiply(ScalarMult
		    .determineNaf(mS, 4), mGArray);

	    // get x- and y-coordinate of mPoint
	    mX = mPoint.getXAffin().toFlexiBigInt();
	    mY = mPoint.getYAffin().toFlexiBigInt();

	    // initialize new state with 2*mX
	    mS = mX.shiftLeft(1);
	    // if y-coordinate is at least (p-1)/2, set mS <-- mS + 1
	    if ((mY.compareTo(mP_minus_1_half)) == 1) {
		mS = mS.add(FlexiBigInt.ONE);
	    }

	    return mCurrentByte;
	}

	// mS is equal to mR
	if (mS.equals(mR)) {

	    // The current byte is the equal to 0
	    mCurrentByte = 0;

	    // The point mPoint is equal to O in E_tw(\F_p)
	    mS = mP.shiftLeft(1); // mS = 2*mP + 1
	    mS.add(FlexiBigInt.ONE);

	    return mCurrentByte;
	}
	// mS_minus_mR = mS - mR
	mS_minus_mR = mS.subtract(mR);

	// compute the current byte
	mCurrentByte = computeB(mS_minus_mR, mR_tw, mR_tw_minus_1_half);

	// mPoint <-- (mS-mR) * mG_tw
	mPoint = (PointGFP) ScalarMult.eval_SquareMultiply(ScalarMult
		.determineNaf(mS_minus_mR, 4), mG_twArray);

	// get x- and y-coordinate of mPoint
	mX = mPoint.getXAffin().toFlexiBigInt();
	mY = mPoint.getYAffin().toFlexiBigInt();

	// mS = 2 * ( mX / mGamma mod mP )
	mS = mX.multiply(mGammaInverse);
	mS = mS.remainder(mP);
	mS = mS.shiftLeft(1);
	// if y-coordinate is at least (p-1)/2, increase mS by 1
	if ((mY.compareTo(mP_minus_1_half)) == 1) {
	    mS = mS.add(FlexiBigInt.ONE);
	}

	return mCurrentByte;
    } // end of method phi()

}
