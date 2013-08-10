/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.mersa;

import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.core.rsa.PKCS1Exception;
import de.flexiprovider.core.rsa.interfaces.RSAPublicKey;

/**
 * This class implements the MultiExponentRSA primitives for
 * encrypting/verifying and decrypting/signing.
 * 
 * @author Erik Dahmen
 * @author Paul Nguentcheu
 */
public final class MeRSAOperations {

    private static final PKCS1Exception encryptionError = new PKCS1Exception(
	    "encryption error");
    private static final PKCS1Exception decryptionError = new PKCS1Exception(
	    "decryption error");

    /**
     * Default constructor (private).
     */
    private MeRSAOperations() {
	// empty
    }

    /**
     * MeRSA encryption primitive MeRSAEP. Functionally equivalent to MeRSAVP1.
     * 
     * @param pubKey
     *                the public MeRSA key
     * @param m
     *                message to be encrypted (MeRSAEP) <b>or</b> signature to
     *                be verified (MeRSAVP1)
     * @return m<sup>e</sup> mod n
     */
    static FlexiBigInt MeRSAEP(RSAPublicKey pubKey, FlexiBigInt m)
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
     * The MultiExponentRSA decryption primitive (MeRSADP).
     * 
     * @param privKey
     *                the private key
     * @param c
     *                ciphertext to be decrypted <b>or</b> plaintext be signed
     * @return c<sup>d</sup> mod n
     */
    public static FlexiBigInt MeRSADP(MeRSAPrivateKey privKey, FlexiBigInt c)
	    throws PKCS1Exception {
	FlexiBigInt n = privKey.getN();
	// FlexiBigInt d = privKey.getD();
	FlexiBigInt p = privKey.getP();
	FlexiBigInt q = privKey.getQ();
	FlexiBigInt k = privKey.getK();
	FlexiBigInt dp = privKey.getDp();
	FlexiBigInt dq = privKey.getDq();
	FlexiBigInt e = privKey.getE();
	FlexiBigInt eInvP = privKey.getEInvP();
	FlexiBigInt pkInvQ = privKey.getCRTCoeff();

	// step 1: check range of ciphertext, 0 <= c < n must hold
	if (c.compareTo(n) > 0 || c.signum() < 0) {
	    throw decryptionError;
	}

	// step 2: decrypt ciphertext mod q
	FlexiBigInt Mq = c.modPow(dq, q);

	// step 3: use Hensel-Lifting to compute c^d mod p^k
	FlexiBigInt K = c.modPow(dp.subtract(FlexiBigInt.ONE), p);
	FlexiBigInt A = (K.multiply(c)).mod(p);
	FlexiBigInt P = p;
	FlexiBigInt F, E, B;
	for (int i = 1; i < k.intValue(); i++) {
	    P = P.multiply(p);
	    F = A.modPow(e, P);
	    E = (c.subtract(F)).mod(P);
	    B = ((E.multiply(K)).multiply(eInvP)).mod(P);
	    A = A.add(B);
	}

	// step 4: recover plaintext using Garners fast CRT algorithm
	FlexiBigInt V = ((Mq.subtract(A)).multiply(pkInvQ)).mod(q);
	A = A.add((p.pow(k.intValue())).multiply(V));

	// step 5: return plaintext
	return A;
    }

}
