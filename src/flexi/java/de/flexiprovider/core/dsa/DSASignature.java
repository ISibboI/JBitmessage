/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.dsa;

import java.io.IOException;

import codec.asn1.ASN1Exception;
import codec.asn1.ASN1Integer;
import codec.asn1.ASN1Sequence;
import de.flexiprovider.api.MessageDigest;
import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.exceptions.SignatureException;
import de.flexiprovider.api.keys.PrivateKey;
import de.flexiprovider.api.keys.PublicKey;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.util.ASN1Tools;
import de.flexiprovider.core.dsa.interfaces.DSAParams;
import de.flexiprovider.core.dsa.interfaces.DSAPrivateKey;
import de.flexiprovider.core.dsa.interfaces.DSAPublicKey;
import de.flexiprovider.core.md.NullDigest;

public abstract class DSASignature extends
		de.flexiprovider.core.dsa.interfaces.DSASignature {

	// the public key
	private DSAPublicKey pubKey;

	// the private key
	private DSAPrivateKey privKey;

	// the source of randomness
	private SecureRandom random;

	// the message digest
	private MessageDigest md;

	// the prime p (obtained from the DSA parameters)
	private FlexiBigInt p;

	// the subprime q (obtained from the DSA parameters)
	private FlexiBigInt q;

	// the generator g (obtained from the DSA parameters)
	private FlexiBigInt g;

	// the bit length of the subprime q
	private int N;

	/*
	 * Inner classes providing concrete implementations of DSA with a variety of
	 * message digests.
	 */

	/**
	 * DSA with SHA1.
	 */
	public static class SHA1 extends DSASignature {

		/**
		 * The OID of SHA1withDSA.
		 */
		public static final String OID = "1.2.840.10040.4.3";

		/**
		 * An alternative OID of SHA1withDSA.
		 */
		public static final String OID2 = "1.3.14.3.2.13";

		/**
		 * An alternative OID of SHA1withDSA.
		 */
		public static final String OID3 = "1.3.14.3.2.27";

		/**
		 * Constructor.
		 */
		public SHA1() {
			super(new de.flexiprovider.core.md.SHA1());
		}
	}

	/**
	 * DSA with SHA224.
	 */
	public static class SHA224 extends DSASignature {

		/**
		 * Constructor.
		 */
		public SHA224() {
			super(new de.flexiprovider.core.md.SHA224());
		}
	}

	/**
	 * DSA with SHA256.
	 */
	public static class SHA256 extends DSASignature {

		/**
		 * Constructor.
		 */
		public SHA256() {
			super(new de.flexiprovider.core.md.SHA256());
		}
	}

	/**
	 * DSA with SHA384.
	 */
	public static class SHA384 extends DSASignature {

		/**
		 * Constructor.
		 */
		public SHA384() {
			super(new de.flexiprovider.core.md.SHA384());
		}
	}

	/**
	 * DSA with SHA512.
	 */
	public static class SHA512 extends DSASignature {

		/**
		 * Constructor.
		 */
		public SHA512() {
			super(new de.flexiprovider.core.md.SHA512());
		}
	}

	/**
	 * Inner class providing DSA without message digest
	 */
	public static class Raw extends DSASignature {

		/**
		 * Constructor.
		 */
		public Raw() {
			super(new NullDigest());
		}
	}

	/**
	 * Inner class providing the DSA ASN.1 signature structure.
	 * <p>
	 * The ASN.1 signature structure is defined as follows:
	 * 
	 * <pre>
	 * DSASignature :== SEQUENCE {
	 *   r  INTEGER,
	 *   s  INTEGER
	 * }
	 * </pre>
	 */
	private static class DSAASN1Signature extends ASN1Sequence {

		// the value r
		private ASN1Integer r;

		// the value s
		private ASN1Integer s;

		/**
		 * Construct a new empty ASN.1 structure (used for decoding).
		 */
		public DSAASN1Signature() {
			super(2);
			r = new ASN1Integer();
			s = new ASN1Integer();

			add(r);
			add(s);
		}

		/**
		 * Construct a new ASN.1 Structure with the given values r and s (used
		 * for encoding).
		 * 
		 * @param r
		 *            the value r
		 * @param s
		 *            the value s
		 */
		public DSAASN1Signature(FlexiBigInt r, FlexiBigInt s) {
			super(2);
			this.r = ASN1Tools.createInteger(r);
			this.s = ASN1Tools.createInteger(s);

			add(this.r);
			add(this.s);
		}

		/**
		 * @return the value r
		 */
		public FlexiBigInt getR() {
			return ASN1Tools.getFlexiBigInt(r);
		}

		/**
		 * @return the value s
		 */
		public FlexiBigInt getS() {
			return ASN1Tools.getFlexiBigInt(s);
		}

	}

	/**
	 * Constructor.
	 * 
	 * @param md
	 *            the message digest to use
	 */
	protected DSASignature(MessageDigest md) {
		this.md = md;
	}

	/**
	 * Initialize the signature algorithm for signing a message.
	 * 
	 * @param privKey
	 *            the private key of the signer
	 * @param random
	 *            the source of randomness
	 * @throws InvalidKeyException
	 *             if the key is not an instance of DSAPrivKey.
	 */
	public void initSign(PrivateKey privKey, SecureRandom random)
			throws InvalidKeyException {
		if (!(privKey instanceof DSAPrivateKey)) {
			throw new InvalidKeyException("unsupported type");
		}
		this.privKey = (DSAPrivateKey) privKey;

		DSAParams dsaParams = this.privKey.getParameters();
		p = dsaParams.getPrimeP();
		q = dsaParams.getPrimeQ();
		g = dsaParams.getBaseG();
		N = q.bitLength();

		this.random = (random == null) ? Registry.getSecureRandom() : random;
	}

	/**
	 * Initialize the signature algorithm for verifying a signature.
	 * 
	 * @param pubKey
	 *            the public key of the signer.
	 * @throws InvalidKeyException
	 *             if the public key is not an instance of DSAPubKey.
	 */
	public void initVerify(PublicKey pubKey) throws InvalidKeyException {
		if (!(pubKey instanceof DSAPublicKey)) {
			throw new InvalidKeyException("unsupported type");
		}
		this.pubKey = (DSAPublicKey) pubKey;

		DSAParams dsaParams = this.pubKey.getParameters();
		p = dsaParams.getPrimeP();
		g = dsaParams.getBaseG();
		q = dsaParams.getPrimeQ();
		N = q.bitLength();
	}

	/**
	 * Initialize this signature engine with the specified parameter set.
	 * 
	 * @param params
	 *            the parameters
	 * @throws InvalidAlgorithmParameterException
	 *             if the given parameters are inappropriate for this signature
	 *             engine
	 */
	public void setParameters(AlgorithmParameterSpec params)
			throws InvalidAlgorithmParameterException {

		if (params != null) {
			if (!(params instanceof DSAParams)) {
				throw new InvalidAlgorithmParameterException("unsupported type");
			}

			DSAParams dsaParams = (DSAParams) params;
			p = dsaParams.getPrimeP();
			q = dsaParams.getPrimeQ();
			g = dsaParams.getBaseG();
		}
	}

	/**
	 * Pass a message byte to the message digest.
	 * 
	 * @param b
	 *            the message byte
	 */
	public void update(byte b) {
		md.update(b);
	}

	/**
	 * Pass message bytes to the message digest.
	 * 
	 * @param b
	 *            the message byte
	 * @param offset
	 *            the index where the message bytes starts
	 * @param length
	 *            the number of message bytes
	 */
	public void update(byte[] b, int offset, int length) {
		md.update(b, offset, length);
	}

	/**
	 * Signs a message. The result is an ASN1 Sequence containing the Integers r
	 * and s. With r = (g<sup>k</sup> mod p) mod q and s = (k<sup>-1</sup>
	 * (SHA(M) + x*r)) mod q.
	 * 
	 * @return the signature (an ASN1 Sequence containing the Integers r and s).
	 * @throws SignatureException
	 *             if the signature is not initialized properly.
	 */
	public byte[] sign() throws SignatureException {
		// compute the message representative
		FlexiBigInt m = computeMessageRepresentative();

		// choose uniformly at random an integer k in the range (1..q)
		FlexiBigInt k;
		do {
			k = new FlexiBigInt(N, random);
		} while (k.compareTo(FlexiBigInt.ONE) <= 0 || k.compareTo(q) >= 0);

		FlexiBigInt kInv = k.modInverse(q);
		FlexiBigInt x = privKey.getValueX();
		FlexiBigInt r = g.modPow(k, p).mod(q);
		FlexiBigInt s = kInv.multiply(m.add(x.multiply(r))).mod(q);

		DSAASN1Signature sig = new DSAASN1Signature(r, s);
		try {
			return ASN1Tools.derEncode(sig);
		} catch (RuntimeException re) {
			throw new SignatureException(re.getMessage());
		}
	}

	/**
	 * Verifies a signature.
	 * 
	 * @param sigBytes
	 *            the signature to be verified
	 * @return <tt>true</tt> if the signature is correct, <tt>false</tt>
	 *         otherwise
	 */
	public boolean verify(byte[] sigBytes) {
		DSAASN1Signature sig = new DSAASN1Signature();
		try {
			// our philosophy: if something goes wrong,
			// reject the signature without further ado.
			ASN1Tools.derDecode(sigBytes, sig);
		} catch (ASN1Exception ae) {
			// indicate failure
			return false;
		} catch (IOException ioe) {
			// indicate failure
			return false;
		}

		// compute the message representative
		FlexiBigInt m = computeMessageRepresentative();

		FlexiBigInt r = sig.getR();
		FlexiBigInt s = sig.getS();
		FlexiBigInt y = pubKey.getValueY();

		// reject the signature if r or s >= q
		if (r.compareTo(q) >= 0 || s.compareTo(q) >= 0) {
			return false;
		}

		FlexiBigInt w = s.modInverse(q);
		FlexiBigInt u1 = (m.multiply(w)).mod(q);
		FlexiBigInt u2 = (r.multiply(w)).mod(q);
		FlexiBigInt v = (((g.modPow(u1, p)).multiply(y.modPow(u2, p))).mod(p))
				.mod(q);

		// if r = v, the signature is valid
		return r.compareTo(v) == 0;
	}

	private FlexiBigInt computeMessageRepresentative() {
		// Let hLen be the output length (in octets) of the hash function. If
		// N (the bit length of the subprime q) is smaller than 8*hLen, the
		// rightmost 8*hLen-N bits of the message digest have to be truncated.
		// This is done by a right shift of the integer generated from the hash
		// value.
		byte[] hash = md.digest();
		FlexiBigInt m = new FlexiBigInt(1, hash);

		int hLen = md.getDigestLength();
		int trunc = 8 * hLen - N;
		if (trunc > 0) {
			m = m.shiftRight(trunc);
		}

		return m;
	}

}
