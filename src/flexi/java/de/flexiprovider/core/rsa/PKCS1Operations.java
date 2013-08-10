/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.rsa;

import codec.pkcs1.DigestInfo;
import de.flexiprovider.api.MessageDigest;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.util.ASN1Tools;
import de.flexiprovider.common.util.ByteUtils;
import de.flexiprovider.core.rsa.interfaces.RSAPrivateCrtKey;
import de.flexiprovider.core.rsa.interfaces.RSAPrivateKey;
import de.flexiprovider.core.rsa.interfaces.RSAPublicKey;
import de.flexiprovider.pki.AlgorithmIdentifier;

public final class PKCS1Operations {
    /*
     * Comments in the following piece of code were excessively snipped from the
     * PKCS#1 v2.1 standard document of the "RSA Security Inc. Public-Key
     * Cryptography Standards (PKCS)"
     * 
     */

    private static final PKCS1Exception encryptionError = new PKCS1Exception(
	    "encryption error");

    private static final PKCS1Exception decryptionError = new PKCS1Exception(
	    "decryption error");

    /**
     * Default constructor (private).
     */
    private PKCS1Operations() {
	// empty
    }

    /**
     * Hash an octet string with the hash function of choice (SHA-1).
     * 
     * @param M
     *                octet string to be hashed
     * @return hash value of octet string
     */
    private static byte[] hash(byte[] M, MessageDigest md) {
	md.reset();
	if (M != null) {
	    md.update(M);
	}
	return md.digest();
    }

    /**
     * Converts a nonnegative integer to an octet string of specified length.
     * 
     * @param x
     *                nonnegative integer to be converted
     * @param xLen
     *                intended maximum length of the resulting octet string or 0
     *                if arbitrary length is allowed. if xLen != 0, the
     *                resulting octet string will be padded with leading zeros.
     * @return corresponding octet string of length <tt>xLen</tt>
     */
    public static byte[] I2OSP(FlexiBigInt x, int xLen) throws PKCS1Exception {
	int len = (x.bitLength() + 7) >> 3;

	// arbitray length octet string allowed
	if (xLen == 0) {
	    xLen = len;
	}

	// step 1: abort if x is too large
	if (len > xLen) {
	    throw new PKCS1Exception("integer too large");
	}

	byte[] tmp = x.toByteArray();
	// check whether byte array is of length xLen already.
	if (tmp.length == xLen) {
	    return tmp;
	}

	byte[] X = new byte[xLen];

	if ((x.bitLength() >> 3 == xLen) && ((x.bitLength() & 7) == 0)) {
	    // toByteArray() appends a leading zero byte for the sign of
	    // the integer which results in the octet string being one byte
	    // to large. this we have to remove.
	    System.arraycopy(tmp, 1, X, 0, xLen);
	} else {
	    // X is already filled with leading zeros. right-align octet
	    // representation of x.
	    System.arraycopy(tmp, 0, X, xLen - tmp.length, tmp.length);
	}

	return X;
    }

    /**
     * Converts an octet string to a nonnegative integer.
     * 
     * @param X
     *                octet string to be converted
     * @return corresponding nonnegative integer
     */
    public static FlexiBigInt OS2IP(byte[] X) {
	return new FlexiBigInt(1, X);
    }

    /**
     * RSA encryption primitive RSAEP. Functionally equivalent to RSAVP1.
     * 
     * @param pubKey
     *                the public RSA key
     * @param m
     *                message to be encrypted (RSAEP) <b>or</b> signature to be
     *                verified (RSAVP1)
     * @return m<sup>d</sup> mod n
     */
    protected static FlexiBigInt RSAEP(RSAPublicKey pubKey, FlexiBigInt m)
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
     * RSA decryption primitive RSADP as specified in PKCS#1, section 5.1.1
     * 
     * No multiprime support. Functionally equivalent to RSASP1.
     * 
     * @param privKey
     *                the private RSA key
     * @param c
     *                ciphertext to be decrypted (RSADP) <b>or</b> plaintext be
     *                signed (RSASP1)
     * @return m<sup>e</sup> mod n
     */
    protected static FlexiBigInt RSADP(RSAPrivateKey privKey, FlexiBigInt c)
	    throws PKCS1Exception {
	FlexiBigInt n = privKey.getN();
	FlexiBigInt d = privKey.getD();

	// step 1: check range of ciphertext, 0 <= c < n must hold
	if (c.compareTo(n) > 0 || c.signum() < 0) {
	    throw decryptionError;
	}

	// ordering is important here, since RSAPrivateCrtKey is a descendant
	// of RSAPrivateKey. DO NOT SWAP!
	if (privKey instanceof RSAPrivateCrtKey) {
	    // step 2b: second form (p, q, dP, dQ, qInv) of K is used
	    RSAPrivateCrtKey crtKey = (RSAPrivateCrtKey) privKey;
	    // extract variables from CRT key.
	    FlexiBigInt p = crtKey.getP();
	    FlexiBigInt q = crtKey.getQ();
	    FlexiBigInt dP = crtKey.getDp();
	    FlexiBigInt dQ = crtKey.getDq();
	    FlexiBigInt qInv = crtKey.getCRTCoeff();
	    // step 2b, i: m_1 = c^{dP} mod n, m_2 = c^{dQ} mod q
	    FlexiBigInt m1 = c.remainder(p).modPow(dP, p);
	    FlexiBigInt m2 = c.remainder(q).modPow(dQ, q);
	    // step 2b, ii: ommitted since only needed for multiprime support
	    // step 2b, iii: h = (m_1 - m_2) * qInv mod P
	    FlexiBigInt h = qInv.multiply(m1.subtract(m2).remainder(p)).mod(p);
	    // step 2b, iv: m = m_2 + q * h
	    return h.multiply(q).add(m2);
	    // step 2b, v: omitted since only needed for multiprime support
	}
	// step 2a: first form (n, d) of K is used, let m = c^m mod n
	return c.modPow(d, n);
    }

    /**
     * EME-OAEP encoding as specified in PKCS#1 v2.1, section 7.1.1, step 2
     * 
     * @param L
     *                a label, optional. pass <tt>null</tt> if label empty.
     * @param M
     *                message to be encoded
     * @param k
     *                the encoding length
     * @param md
     *                message digest that will be used for hashing the message
     * @param prng
     *                source of cryptographically secure pseudo-randomness
     * @return encoded message EM
     */
    public static byte[] EME_OAEP_ENCODE(byte[] M, byte[] L, int k,
	    MessageDigest md, SecureRandom prng) {
	// a) lHash = Hash(L), if L is not provided, hash the empty string
	byte[] lHash = hash(L, md);
	int hLen = lHash.length;

	// b) no need to generate zero octets for PS. this step is superfluos.
	// c) concatenate, lHash, PS, single octet of hexadecimal value 0x01
	// and the message M to form a data block of length k - hLen - 1.
	// DB = lHash || PS || 0x01 || M
	byte[] DB = new byte[k - hLen - 1];
	System.arraycopy(lHash, 0, DB, 0, hLen);
	DB[DB.length - M.length - 1] = 0x01;
	System.arraycopy(M, 0, DB, DB.length - M.length, M.length);

	// d) generate a random octet string seed of length hLen
	byte[] seed = new byte[hLen];
	prng.nextBytes(seed);
	// e) Let dbMask = MGF (seed, k - hLen - 1)
	byte[] dbMask = MGF1(seed, k - hLen - 1, md);
	// f) Let maskedDB = DB ^ dbMask
	byte[] maskedDB = ByteUtils.xor(DB, dbMask);
	// g) Let seedMask = MGF (maskedDB, hLen)
	byte[] seedMask = MGF1(maskedDB, hLen, md);
	// h) Let maskedSeed = seed ^ seedMask
	byte[] maskedSeed = ByteUtils.xor(seed, seedMask);
	// i) Concatenate a single octet with hexadecimal value 0x00,
	// maskedSeed and maskedDB to form an encoded message EM of
	// length k octets as
	byte[] EM = new byte[k];
	System.arraycopy(maskedSeed, 0, EM, 1, maskedSeed.length);
	System.arraycopy(maskedDB, 0, EM, 1 + maskedSeed.length,
		maskedDB.length);

	// output EM
	return EM;
    }

    /**
     * EME-OAEP decoding as specified in PKCS#1 v2.1, section 7.1.2, step 3
     * 
     * @param EM
     *                the encoded message
     * @param L
     *                a label, optional. pass <tt>null</tt> if not required.
     * @param k
     *                the encoding length
     * @param md
     *                the message digest
     * @return encoded message EM
     */
    public static byte[] EME_OAEP_DECODE(byte[] EM, byte[] L, int k,
	    MessageDigest md) throws PKCS1Exception {
	boolean error = false;
	// a) lHash = Hash(L), if L is not provided, hash the empty string
	byte[] lHash = hash(L, md);
	int hLen = lHash.length;

	// b) Seperate the encoded message into a single octet Y, an octet
	// string
	// maskedSeed of length hLen, and an octet string maskedDB of length
	// k - hLen - 1 as: EM = Y || maskedSeed || maskedDB.
	byte Y = EM[0];
	byte[] maskedSeed = new byte[hLen];
	byte[] maskedDB = new byte[k - hLen - 1];
	System.arraycopy(EM, 1, maskedSeed, 0, hLen);
	System.arraycopy(EM, 1 + hLen, maskedDB, 0, k - hLen - 1);

	// c) Let seedMask = MGF (maskedDB, hLen)
	byte[] seedMask = MGF1(maskedDB, hLen, md);
	// d) seed = maskedSeed ^ seedMask
	byte[] seed = ByteUtils.xor(maskedSeed, seedMask);
	// e) Let dbMask = MGF (seed, k - hLen - 1)
	byte[] dbMask = MGF1(seed, k - hLen - 1, md);
	// f) Let DB = maskedDB ^ dbMask
	byte[] DB = ByteUtils.xor(maskedDB, dbMask);

	// g) seperate DB into an octet string lHash' of length
	// hLen, a (possibly empty) padding string PS consisting
	// of octets with hexadecimal value 0x00 and a message M
	// such that DB = lHash' || PS || 0x01 || M
	byte[] lHash2 = new byte[hLen];
	System.arraycopy(DB, 0, lHash2, 0, hLen);
	int pos = hLen;

	while (DB[pos] != 0x01 && pos < (DB.length - 1)) {
	    if (DB[pos] != 0x00) {
		// defer exception to avoid timing attacks
		error = true;
	    }
	    pos++;
	}
	if (DB[pos] != 0x01) {
	    // defer exception to avoid timing attacks
	    error = true;
	}
	byte[] M = new byte[DB.length - pos - 1];
	System.arraycopy(DB, pos + 1, M, 0, DB.length - pos - 1);

	// deferred exceptions are thrown here
	if (!ByteUtils.equals(lHash, lHash2) || Y != 0x00 || error) {
	    throw decryptionError;
	}

	// output EM
	return M;
    }

    public static byte[] EMSA_PSS_ENCODE(byte[] M, int emBits,
	    MessageDigest md, byte[] salt) throws PKCS1Exception {
	byte[] mHash, maskedDB, H, dbMask, DB, M2, EM;
	int hLen = md.getDigestLength();
	int emLen = (emBits + 7) >> 3;
	int sLen = salt.length;

	// 1) If the length of M is greater than the input limitation for the
	// hash function (2^61-1 octets for SHA-1), output "message too long"
	// and stop.
	if (M.length > 0x1fffffffffffffffL) {
	    throw new PKCS1Exception("message too long");
	}

	// 2) Let mHash = Hash (M), an octet string of length hLen.
	mHash = hash(M, md);

	// 3) If emLen < hLen + sLen + 2, output "encoding error" and stop.
	if (emLen < (hLen + sLen + 2)) {
	    throw new PKCS1Exception("encoding error");
	}

	// 4) Generate a random octet string salt of length sLen;
	// if sLen = 0, then salt is the empty string.
	// NOT NECESSARY, WE TAKE THE SALT AS AN ARGUMENT

	// 5) Let M2 = (0x)00 00 00 00 00 00 00 00 || mHash || salt; M is an
	// octet
	// string of length 8+hLen+sLen with eight initial zero octets.
	M2 = new byte[8 + hLen + sLen];
	System.arraycopy(mHash, 0, M2, 8, hLen);
	System.arraycopy(salt, 0, M2, 8 + hLen, sLen);
	// 6) Let H2 = Hash (M2), an octet string of length hLen.
	H = hash(M2, md);

	// 7) Generate an octet string PS consisting of emLen-sLen-hLen-2 zero
	// octets.
	// The length of PS may be 0. THIS STEP IS SUPERFLUOUS IN OUR
	// IMPLEMENTATION.
	// 8) Let DB = PS || 0x01 || salt; DB is an octet string of length
	// emLen-hLen-1.
	DB = new byte[emLen - hLen - 1];
	DB[DB.length - sLen - 1] = 0x01;
	System.arraycopy(salt, 0, DB, DB.length - sLen, sLen);

	// 9) Let dbMask = MGF (H, emLen-hLen-1).
	dbMask = MGF1(H, emLen - hLen - 1, md);

	// 10) Let maskedDB = DB XOR dbMask
	maskedDB = ByteUtils.xor(DB, dbMask);

	// 11) Set the leftmost 8*emLen-emBits bits of the leftmost octet in
	// maskedDB to zero.
	maskedDB[0] &= (1 << (8 - (8 * emLen - emBits))) - 1;

	// 12) Let EM = maskedDB || H || 0xbc.
	EM = new byte[emLen];
	System.arraycopy(maskedDB, 0, EM, 0, maskedDB.length);
	System.arraycopy(H, 0, EM, maskedDB.length, hLen);
	EM[EM.length - 1] = (byte) 0xbc;

	// 13) output EM
	return EM;
    }

    /**
     * This encoding method is parameterized by the choice of hash function,
     * mask generation function, and salt length. These options should be fixed
     * for a given RSA key, except that the salt length can be variable.
     * Suggested hash and mask generation functions are given in Appendix B. The
     * encoding method is based on Bellare and Rogaway's Probabilistic Signature
     * Scheme (PSS) [4][5]. It is randomized and has an encoding operation and a
     * verification operation.
     * 
     * @param M
     *                the message
     * @param EM
     *                the encoded message
     * @param emBits
     *                the bit length of the encoded message
     * @param md
     *                the message digest
     * @return whether <tt>EM</tt> is a valid encoding of <tt>M</tt>
     */
    public static boolean EMSA_PSS_VERIFY(byte[] M, byte[] EM, int emBits,
	    MessageDigest md) {
	byte[] mHash, maskedDB, H, dbMask, DB, M2, H2;
	int hLen = md.getDigestLength(), emLen = EM.length, sLen, i;

	// 1) If the length of M is greater than the input limitation for the
	// hash function (2^61-1 octets for SHA-1), output "inconsistent" and
	// stop.
	if (M.length > 0x1fffffffffffffffL) {
	    return false;
	}

	// 2) Let mHash = Hash (M), an octet string of length hLen.
	mHash = hash(M, md);

	// 3) If emLen < hLen + sLen + 2, output "inconsistent" and stop.
	// we do not know the value of sLen at this time. assume a minimum of 0.
	// 4) If the rightmost octet of EM does not have hexadecimal value 0xbc,
	// output "inconsistent" and stop.
	if (emLen < hLen + 2 || (EM[emLen - 1] & 0xff) != 0xbc) {
	    return false;
	}

	// 5) Let maskedDB be the leftmost emLen-hLen-1 octets of EM, and let H
	// be the next hLen octets.
	maskedDB = new byte[emLen - hLen - 1];
	H = new byte[hLen];
	System.arraycopy(EM, 0, maskedDB, 0, maskedDB.length);
	System.arraycopy(EM, maskedDB.length, H, 0, H.length);

	// 6) If the leftmost 8*emLen-emBits bits of the leftmost octet in
	// maskedDB
	// are not all equal to zero, output "inconsistent" and stop.
	int bitMask = (1 << (8 - (8 * emLen - emBits))) - 1;
	if ((maskedDB[0] & (~bitMask)) != 0) {
	    return false;
	}

	// 7) Let dbMask = MGF (H, emLen-hLen-1).
	dbMask = MGF1(H, emLen - hLen - 1, md);

	// 8) Let DB = maskedDB XOR dbMask
	DB = ByteUtils.xor(maskedDB, dbMask);

	// 9) Set the leftmost 8*emLen-emBits bits of the leftmost octet in DB
	// to zero.
	DB[0] &= bitMask;
	// 10) If the emLen-hLen-sLen-2 leftmost octets of DB are not zero...
	for (i = 0; DB[i] == 0 && i < DB.length - 1; i++) {
	    ;
	}
	// ... or if the octet at position emLen-hLen-sLen-1 (the leftmost
	// position is
	// position 1) does not have hexadecimal value 0x01, output
	// "inconsistent" and stop.
	if (DB[i++] != 0x01) {
	    return false;
	}
	sLen = DB.length - i;

	// at this point we know sLen, thus we can re-check the condition in
	// step 3)
	if (emLen < hLen + sLen + 2) {
	    return false;
	}

	// 11) Let salt be the last sLen octets of DB
	// 12) Let M2 = (0x)00 00 00 00 00 00 00 00 || mHash || salt
	// M is an octet string of length 8+hLen+sLen with eight initial zero
	// octets.
	M2 = new byte[8 + hLen + sLen];
	System.arraycopy(mHash, 0, M2, 8, hLen);
	System.arraycopy(DB, i, M2, 8 + hLen, sLen);
	// 13) Let H2 = Hash (M2), an octet string of length hLen.
	H2 = hash(M2, md);

	// 14) If H = H2, output "consistent". Otherwise, output "inconsistent".
	return ByteUtils.equals(H, H2);
    }

    /**
     * This encoding method is deterministic and does not have an equivalent
     * decoding function.
     * 
     * @param H
     *                hash value of the message to be encoded (deviant from
     *                specification)
     * @param emLen
     *                intended length in octets of the encoded message at least
     *                tLen+11, where tLen is the octet length of the DER
     *                encoding T of a certain value computed during the encoding
     *                operation.
     * @param aid
     *                Algorithm identifier of the message digest algorithm used
     *                for hashing the message.
     * @return the encoded message
     */
    public static byte[] EMSA_PKCS1_v1_5_ENCODE(byte[] H, int emLen,
	    AlgorithmIdentifier aid) throws PKCS1Exception {

	// 1) Apply the hash function to the message M to produce a hash value H
	// H = Hash(M). THIS STEP HAS BEEN PERFORMED ALREADY.
	DigestInfo digestInfo = new DigestInfo(aid, H);
	byte[] T = ASN1Tools.derEncode(digestInfo);

	int tLen = T.length;

	if (emLen < tLen) {
	    throw new PKCS1Exception(
		    "intended encoded message length too short.");
	}

	byte[] EM = new byte[emLen];

	EM[0] = 0x00;
	EM[1] = 0x01;
	int i;
	for (i = 2; i < emLen - tLen - 1; i++) {
	    EM[i] = (byte) 0xff;
	}
	EM[i] = 0x00;
	System.arraycopy(T, 0, EM, emLen - tLen, tLen);
	return EM;
    }

    /**
     * Mask generation function MGF1 as specified in PKCS#1, section B.2
     * Coincides with mask generation functions specified in IEEE Standard 1363
     * and ANSI X9.44 (draft).
     * 
     * @param seed
     *                the seed
     * @param length
     *                the intended output length
     * @param md
     *                the message digest
     * @return the generated mask
     */
    public static byte[] MGF1(byte[] seed, int length, MessageDigest md) {
	int digestLength = md.getDigestLength();
	int end = length / digestLength;
	byte[] c = new byte[4], digest;
	byte[] out = new byte[length];

	md.reset();
	for (int counter = 0; counter <= end; counter++) {
	    c[0] = (byte) ((counter >> 24) & 0xff);
	    c[1] = (byte) ((counter >> 16) & 0xff);
	    c[2] = (byte) ((counter >> 8) & 0xff);
	    c[3] = (byte) (counter & 0xff);
	    md.update(seed);
	    digest = md.digest(c);
	    if (counter < end) {
		System.arraycopy(digest, 0, out, counter * digestLength,
			digestLength);
	    } else {
		System.arraycopy(digest, 0, out, counter * digestLength, length
			- counter * digestLength);
	    }
	}
	return out;
    }
}
