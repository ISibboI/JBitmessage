/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.mprsa;

import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.core.rsa.PKCS1Exception;
import de.flexiprovider.core.rsa.interfaces.RSAPublicKey;

/**
 * This class implements the Multi-Prime RSA primitives for encrypting/verifying
 * and decrypting/signing.
 * 
 * @author Paul Nguentcheu
 */
public final class MpRSAOperations {

    private static final PKCS1Exception encryptionError = new PKCS1Exception(
	    "encryption error");
    private static final PKCS1Exception decryptionError = new PKCS1Exception(
	    "decryption error");

    /**
     * Default constructor (private).
     */
    private MpRSAOperations() {
	// empty
    }

    /**
     * Multi-Prime encryption primitive MpRSAEP. Functionally equivalent to
     * MpRSAVP1.
     * 
     * @param pubKey
     *                the public MpRSA key
     * @param m
     *                message to be encrypted (MpRSAEP) <b>or</b> signature to
     *                be verified (MpRSAVP1)
     * @return m<sup>e</sup> mod n
     */
    static FlexiBigInt MpRSAEP(RSAPublicKey pubKey, FlexiBigInt m)
	    throws PKCS1Exception {
	FlexiBigInt n = pubKey.getN();
	FlexiBigInt e = pubKey.getE();

	if (m.compareTo(n) > 0 || m.signum() < 0) {
	    throw encryptionError;
	}

	if (e.equals(FlexiBigInt.valueOf(3))) {
	    return m.multiply(m).mod(n).multiply(m).mod(n);
	}
	return m.modPow(e, n);
    }

    /**
     * The Multi-Prime RSA decryption primitive (MpRSADP).
     * 
     * @param privKey
     *                the private key
     * @param c
     *                ciphertext to be decrypted <b>or</b> plaintext be signed
     * @return c<sup>d</sup> mod n
     */
    static FlexiBigInt MpRSADP(MpRSAPrivateKey privKey, FlexiBigInt c)
	    throws PKCS1Exception {

	FlexiBigInt ri, mdi, ti;
	FlexiBigInt n = privKey.getN();
	// extract variables from CRT key.
	FlexiBigInt p = privKey.getP();
	FlexiBigInt q = privKey.getQ();
	FlexiBigInt dP = privKey.getDp();
	FlexiBigInt dQ = privKey.getDq();
	FlexiBigInt qInv = privKey.getCRTCoeff();
	// BigInteger d = privKey.getPrivateExponent();

	// step 1: check range of ciphertext, 0 <= c < n must hold
	if (c.compareTo(n) > 0 || c.signum() < 0) {
	    throw decryptionError;
	}

	if (privKey.getOtherPrimeInfo() == null) {
	    throw decryptionError;
	}

	RSAOtherPrimeInfo[] otherP = privKey.getOtherPrimeInfo();
	int k = otherP.length;

	// step 2: decrypt ciphertext mod q

	// step 2b, i: m_1 = c^{dP} mod p, m_2 = c^{dQ} mod q
	FlexiBigInt m1 = c.remainder(p).modPow(dP, p);
	FlexiBigInt m2 = c.remainder(q).modPow(dQ, q);

	// step 2b, ii: h = (m_1 - m_2) * qInv mod P
	FlexiBigInt h = qInv.multiply(m1.subtract(m2)).mod(p);
	// step 2b, iii: m = m_2 + q * h
	FlexiBigInt m = h.multiply(q).add(m2);

	// step 2b, iv: m = m + R * h, recover plaintext
	FlexiBigInt R = p.multiply(q);

	for (int i = 0; i < k; i++) {
	    ri = otherP[i].getPrime();
	    mdi = otherP[i].getExponent();
	    ti = otherP[i].getCrtCoefficient();
	    mdi = c.remainder(ri).modPow(mdi, ri);
	    h = ti.multiply(mdi.subtract(m)).mod(ri);
	    m = h.multiply(R).add(m);
	    R = R.multiply(ri);
	}
	return m;
    }

}
