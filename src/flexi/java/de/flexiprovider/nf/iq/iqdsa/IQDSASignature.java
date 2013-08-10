package de.flexiprovider.nf.iq.iqdsa;

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
import de.flexiprovider.common.math.quadraticfields.IQClassGroup;
import de.flexiprovider.common.math.quadraticfields.IQEncodingException;
import de.flexiprovider.common.math.quadraticfields.QuadraticIdeal;
import de.flexiprovider.common.util.ASN1Tools;

/**
 * This class implements the core parts of the IQDSA algorithm, namely the
 * signature and the verification process.
 * 
 * @author Ralf-P. Weinmann
 */
public abstract class IQDSASignature extends Signature {

    private SecureRandom random;

    private MessageDigest md;

    private IQClassGroup classGroup;

    private FlexiBigInt a;

    private QuadraticIdeal gamma, alpha;

    private IQDSAParameterSpec params;

    // array of precomputed powers of gamma used to speed up signing
    private QuadraticIdeal[] powersOfGamma;

    /**
     * Inner class providing the IQDSA ASN.1 signature structure.
     * <p>
     * The ASN.1 signature structure is defined as follows:
     * 
     * <pre>
     * IQDSA-Signature ::= SEQUENCE {
     *   Quadratic-Ideal rho,
     *   INTEGER s
     * }
     * 
     * Quadratic-Ideal ::= OCTET STRING
     * </pre>
     */
    private static class IQDSAASN1Signature extends ASN1Sequence {

	private ASN1OctetString rho;

	private ASN1Integer s;

	public IQDSAASN1Signature() {
	    super(2);
	    rho = new ASN1OctetString();
	    s = new ASN1Integer();
	    add(rho);
	    add(s);
	}

	public IQDSAASN1Signature(FlexiBigInt discriminant, QuadraticIdeal rho,
		FlexiBigInt s) {
	    super(2);
	    this.rho = new ASN1OctetString(rho.idealToOctets(discriminant,
		    false));
	    this.s = new ASN1Integer(s.toByteArray());
	    add(this.rho);
	    add(this.s);
	}

	public QuadraticIdeal getRho(FlexiBigInt discriminant)
		throws IQEncodingException {
	    return QuadraticIdeal.octetsToIdeal(discriminant, rho
		    .getByteArray());
	}

	public FlexiBigInt getS() {
	    return ASN1Tools.getFlexiBigInt(s);
	}

    }

    /*
     * Inner classes providing concrete implementations of IQDSA with various
     * message digests.
     */

    /**
     * IQDSA with SHA1 message digest.
     */
    public static class SHA1 extends IQDSASignature {

	/**
	 * The OID of IQDSAwithSHA1.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.1.2";

	public SHA1() {
	    super(new de.flexiprovider.core.md.SHA1());
	}
    }

    /**
     * IQDSA with RIPEMD160 message digest.
     */
    public static class RIPEMD160 extends IQDSASignature {

	/**
	 * The OID of IQDSAwithRIPEMD160.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.1.3";

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
    protected IQDSASignature(MessageDigest md) {
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
     *                 if the key is not an instance of {@link IQDSAPrivateKey}.
     * @see #sign()
     */
    public void initSign(PrivateKey key, SecureRandom prng)
	    throws InvalidKeyException {
	md.reset();

	if (!(key instanceof IQDSAPrivateKey)) {
	    throw new InvalidKeyException("unsupported type");
	}
	IQDSAPrivateKey privKey = (IQDSAPrivateKey) key;

	params = privKey.getParams();
	classGroup = new IQClassGroup(params.getDiscriminant(), prng);
	gamma = params.getGamma();
	a = privKey.getA();

	// precompute powers of gamma for fast computation of rho in signature
	// step
	powersOfGamma = classGroup.precomputeGordonBrickell(gamma, 401);

	this.random = prng != null ? prng : Registry.getSecureRandom();
    }

    /**
     * Initialized engine for verification process
     * 
     * @param key
     *                public key to be used for verification
     * @throws InvalidKeyException
     *                 if the key is not an instance of {@link IQDSAPublicKey}.
     * @see #verify(byte [])
     */
    public void initVerify(PublicKey key) throws InvalidKeyException {
	md.reset();
	if (!(key instanceof IQDSAPublicKey)) {
	    throw new InvalidKeyException("unsupported type");
	}
	IQDSAPublicKey pubKey = (IQDSAPublicKey) key;

	params = pubKey.getParams();
	classGroup = new IQClassGroup(params.getDiscriminant());
	alpha = pubKey.getAlpha();
	gamma = params.getGamma();
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
	QuadraticIdeal rho;
	FlexiBigInt h, k, s;

	// random 400 bit integer
	k = new FlexiBigInt(400, random).setBit(400 - 1);

	if (powersOfGamma != null) {
	    rho = classGroup.power(powersOfGamma, k);
	} else {
	    rho = classGroup.power(gamma, k);
	}

	// h = hash(rho||M)
	md.update(rho.idealToOctets(classGroup, false));

	h = new FlexiBigInt(1, md.digest());
	// s = k - ah
	s = k.subtract(a.multiply(h));

	// create an ASN.1 sequence from the signature (rho, s)
	IQDSAASN1Signature sigValue = new IQDSAASN1Signature(classGroup
		.getDiscriminant(), rho, s);

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
	QuadraticIdeal rho;
	FlexiBigInt h, s;

	IQDSAASN1Signature sigValue = new IQDSAASN1Signature();
	try {
	    ASN1Tools.derDecode(sigBytes, sigValue);
	    rho = sigValue.getRho(classGroup.getDiscriminant());
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

	// h = hash(rho||M)
	md.update(rho.idealToOctets(classGroup, false));

	h = new FlexiBigInt(1, md.digest());

	FlexiBigInt[] exps = { s, h };
	QuadraticIdeal[] bases = { gamma, alpha };
	QuadraticIdeal[][] gLUT = classGroup.precomputeSimPowerWNAF(bases, 3);
	return rho.equals(classGroup.simPowerWNAF(gLUT, exps, 3));
    }

    /**
     * Set the parameters for the signature.
     * 
     * @param params
     *                the parameters
     * @throws InvalidAlgorithmParameterException
     *                 if the parameters are not an instance of
     *                 {@link IQDSAParameterSpec}.
     */
    public void setParameters(AlgorithmParameterSpec params)
	    throws InvalidAlgorithmParameterException {
	if (!(params instanceof IQDSAParameterSpec)) {
	    throw new InvalidAlgorithmParameterException("unsupported type");
	}
	this.params = (IQDSAParameterSpec) params;
	classGroup = new IQClassGroup(this.params.getDiscriminant());
	gamma = this.params.getGamma();
    }

}
