package de.flexiprovider.nf.iq.iqrdsa;

import java.io.IOException;

import codec.asn1.ASN1Exception;
import codec.asn1.ASN1Integer;
import codec.asn1.ASN1OctetString;
import codec.asn1.ASN1Sequence;
import de.flexiprovider.api.MessageDigest;
import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.Signature;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.exceptions.SignatureException;
import de.flexiprovider.api.keys.PrivateKey;
import de.flexiprovider.api.keys.PublicKey;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.math.IntegerFunctions;
import de.flexiprovider.common.math.quadraticfields.IQClassGroup;
import de.flexiprovider.common.math.quadraticfields.IQEncodingException;
import de.flexiprovider.common.math.quadraticfields.QuadraticIdeal;
import de.flexiprovider.common.util.ASN1Tools;

/**
 * The <tt>IQRDSASignature</tt> class implements core parts of the IQRDSA
 * algorithm, namely the signature and the verification process.
 * <p>
 * Signature is generated as follow
 * <p>
 * <li> Randomly select an integer k such that 0 <= 0 < q
 * <li> Compute rho = gamma^k
 * <li> Calculate x = -a * h(M||rho) + k
 * <li> Determine integers s and l such that x = lq + s with 0 <= s < q
 * <li> If s = 0 restart signature step with a different k
 * <li> Compute lambda = gamma^l
 * <p>
 * The signature of the message M is S = (s, rho, lambda)
 * <p>
 * <p>
 * Verification of a given signature only succeeds if the following equation is
 * fulfilled:
 * <p>
 * gamma^s * alpha^h(M||rho) * lambda^q = rho with 1 <= s < q
 * 
 * @author Ralf-P. Weinmann
 */
public abstract class IQRDSASignature extends Signature {

    private SecureRandom random;

    private MessageDigest md;

    private IQClassGroup classGroup;

    private FlexiBigInt modulus, a;

    private QuadraticIdeal gamma, alpha;

    private IQRDSAParameterSpec params;

    // array of precomputed powers of gamma used to speed up signing
    private QuadraticIdeal[] powersOfGamma;

    /**
     * Inner class providing the IQRDSA ASN.1 signature structure.
     * <p>
     * The ASN.1 signature structure is defined as follows:
     * 
     * <pre>
     * IQRDSA-Signature ::= SEQUENCE {
     *   rho     Quadratic-Ideal,
     *   lambda  Quadratic-Ideal,
     *   s       INTEGER
     * }
     * 
     * Quadratic-Ideal ::= OCTET STRING
     * </pre>
     */
    private static class IQRDSAASN1Signature extends ASN1Sequence {

	private ASN1OctetString rho_;

	private ASN1OctetString lambda_;

	private ASN1Integer s_;

	public IQRDSAASN1Signature() {
	    super(3);
	    rho_ = new ASN1OctetString();
	    lambda_ = new ASN1OctetString();
	    s_ = new ASN1Integer();
	    add(rho_);
	    add(lambda_);
	    add(s_);
	}

	public IQRDSAASN1Signature(FlexiBigInt discriminant,
		QuadraticIdeal rho, QuadraticIdeal lambda, FlexiBigInt s) {
	    super(3);
	    rho_ = new ASN1OctetString(rho.idealToOctets(discriminant, false));
	    lambda_ = new ASN1OctetString(lambda.idealToOctets(discriminant,
		    false));
	    s_ = new ASN1Integer(s.toByteArray());
	    add(rho_);
	    add(lambda_);
	    add(s_);
	}

	public QuadraticIdeal getRho(FlexiBigInt discriminant)
		throws IQEncodingException {
	    return QuadraticIdeal.octetsToIdeal(discriminant, rho_
		    .getByteArray());
	}

	public QuadraticIdeal getLambda(FlexiBigInt discriminant)
		throws IQEncodingException {
	    return QuadraticIdeal.octetsToIdeal(discriminant, lambda_
		    .getByteArray());
	}

	public FlexiBigInt getS() {
	    return ASN1Tools.getFlexiBigInt(s_);
	}

    }

    /*
     * Inner classes providing concrete implementations of IQRDSA with various
     * message digests.
     */

    /**
     * IQRDSA with SHA1 message digest.
     */
    public static class SHA1 extends IQRDSASignature {

	/**
	 * The OID of IQRDSAwithSHA1.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.1.8";

	public SHA1() {
	    super(new de.flexiprovider.core.md.SHA1());
	}
    }

    /**
     * IQRDSA with RIPEMD160 message digest.
     */
    public static class RIPEMD160 extends IQRDSASignature {

	/**
	 * The OID of IQRDSAwithRIPEMD160.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.1.9";

	public RIPEMD160() {
	    super(new de.flexiprovider.core.md.RIPEMD160());
	}
    }

    /**
     * Constructor. Set the message digest.
     * 
     * @param md
     *                the message digest
     */
    protected IQRDSASignature(MessageDigest md) {
	this.md = md;
    }

    /**
     * Initializes engine for signing.
     * 
     * @param key
     *                private key to be used for signing
     * @param prng
     *                source of randomness
     * @throws InvalidKeyException
     *                 if the key is not an instance of {@link IQRDSAPrivateKey}.
     * @see #sign()
     */
    public void initSign(PrivateKey key, SecureRandom prng)
	    throws InvalidKeyException {
	md.reset();

	if (!(key instanceof IQRDSAPrivateKey)) {
	    throw new InvalidKeyException("unsupported type");
	}
	IQRDSAPrivateKey privKey = (IQRDSAPrivateKey) key;

	params = privKey.getParams();
	classGroup = new IQClassGroup(params.getDiscriminant(), random);
	modulus = params.getModulus();
	gamma = privKey.getGamma();
	alpha = privKey.getAlpha();
	a = privKey.getA();

	// precompute powers of gamma for fast computation of rho in signature
	// step
	// rho = gamma^k where k is a value in the range [ 2 .. modulus ]
	// XXX: bitLength() + 1 really is necessary here !!!
	powersOfGamma = classGroup.precomputeGordonBrickell(gamma, modulus
		.bitLength() + 1);

	this.random = prng != null ? prng : Registry.getSecureRandom();
    }

    /**
     * Initialized engine for verification process
     * 
     * @param key
     *                public key to be used for verification
     * @throws InvalidKeyException
     *                 if the key is not an instance of {@link IQRDSAPublicKey}.
     * @see #verify(byte [])
     */
    public void initVerify(PublicKey key) throws InvalidKeyException {
	md.reset();

	if (!(key instanceof IQRDSAPublicKey)) {
	    throw new InvalidKeyException("unsupported type");
	}
	IQRDSAPublicKey pubKey = (IQRDSAPublicKey) key;

	params = pubKey.getParams();
	classGroup = new IQClassGroup(params.getDiscriminant());
	modulus = params.getModulus();
	gamma = pubKey.getGamma();
	alpha = pubKey.getAlpha();
    }

    /**
     * Updates the data to be signed or verified using the specified byte.
     * 
     * @param b
     *                the byte to be updated.
     */
    public void update(byte b) {
	md.update(b);
    }

    /**
     * Updates the data to be signed or verified, using the specified array of
     * bytes, starting at the specified offset.
     * 
     * @param b
     *                the byte array
     * @param off
     *                the offset to start from in the array of bytes
     * @param len
     *                the number of bytes to use, starting at offset
     */
    public void update(byte[] b, int off, int len) {
	md.update(b, off, len > 0 ? len : 0);
    }

    /**
     * Calculates the digest value for a given octet string
     * 
     * @param m
     *                array containing the data to be hashed
     * 
     * @return the digest value represented as an octet string
     */
    protected byte[] makeDigest(byte[] m) {
	return md.digest(m);
    }

    /**
     * Generates an ASN.1 encoded object representing the signature of the data
     * bytes digested by the message digest algorithm thus far.
     * 
     * @return signature of the data fed into the engine thus far
     */
    public byte[] sign() {
	QuadraticIdeal rho, lambda;
	FlexiBigInt h, k, l, s, x;
	FlexiBigInt[] qr;

	// choose a random k
	k = IntegerFunctions.randomize(
		modulus.subtract(FlexiBigInt.valueOf(2)), random).add(
		FlexiBigInt.valueOf(2));

	rho = classGroup.power(powersOfGamma, k);

	// 2000-06-20 fix in updated version of paper: $x = -ah(M||\rho) + k$
	md.update(rho.idealToOctets(classGroup, false));

	h = new FlexiBigInt(1, md.digest());

	x = k.subtract(h.multiply(a));

	qr = x.divideAndRemainder(modulus);
	l = qr[0];
	s = qr[1];
	lambda = classGroup.power(powersOfGamma, l);

	// encode the signature (rho, lambda, s) as ASN.1 sequence
	IQRDSAASN1Signature sigValue = new IQRDSAASN1Signature(classGroup
		.getDiscriminant(), rho, lambda, s);

	// return the DER encoded ASN.1 sequence
	return ASN1Tools.derEncode(sigValue);
    }

    /**
     * Verifies the signature passed in as <tt>sigBytes</tt>
     * 
     * @param sigBytes
     *                the signature bytes to be verified.
     * @return <tt>true</tt> if the signature was verified, <tt>false</tt>
     *         if not.
     * @throws SignatureException
     *                 if this signature object is not initialized properly.
     */
    public boolean verify(byte[] sigBytes) throws SignatureException {
	QuadraticIdeal rho, lambda;
	FlexiBigInt h, s;

	IQRDSAASN1Signature sigValue = new IQRDSAASN1Signature();
	try {
	    ASN1Tools.derDecode(sigBytes, sigValue);
	    rho = sigValue.getRho(classGroup.getDiscriminant());
	    lambda = sigValue.getLambda(classGroup.getDiscriminant());
	} catch (ASN1Exception asn1e) {
	    throw new SignatureException(
		    "ASN1Exception: can not decode signature: "
			    + asn1e.getMessage());
	} catch (IOException ioe) {
	    throw new SignatureException("IOException: " + ioe.getMessage());
	} catch (IQEncodingException iqee) {
	    throw new SignatureException("IQEncodingException: "
		    + iqee.getMessage());
	}

	s = sigValue.getS();

	// 2000-06-20 fix in updated version of paper: $x = -ah(M||\rho) + k$
	md.update(rho.idealToOctets(classGroup, false));

	h = new FlexiBigInt(1, md.digest());

	// t = alpha^phi(rho, p) * rho^h * gamma^(-s) * lambda^(-p)
	FlexiBigInt[] exponents = new FlexiBigInt[] { s, h, modulus };
	QuadraticIdeal[] bases = new QuadraticIdeal[] { gamma, alpha, lambda };

	QuadraticIdeal[][] gLUT = classGroup.precomputeSimPowerWNAF(bases, 2);

	return rho.equals(classGroup.simPowerWNAF(gLUT, exponents, 2));
    }

    /**
     * Set the parameters for the signature.
     * 
     * @param params
     *                the parameters
     * @throws InvalidAlgorithmParameterException
     *                 if the parameters are not an instance of
     *                 {@link IQRDSAParameterSpec}.
     */
    public void setParameters(AlgorithmParameterSpec params)
	    throws InvalidAlgorithmParameterException {
	if (!(params instanceof IQRDSAParameterSpec)) {
	    throw new InvalidAlgorithmParameterException("unsupported type");
	}

	this.params = (IQRDSAParameterSpec) params;
    }

}
