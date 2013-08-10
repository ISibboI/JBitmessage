package de.flexiprovider.pqc.ots.lm;

import java.util.Vector;

import de.flexiprovider.api.MessageDigest;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.Signature;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.exceptions.SignatureException;
import de.flexiprovider.api.keys.PrivateKey;
import de.flexiprovider.api.keys.PublicKey;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.math.IntegerFunctions;
import de.flexiprovider.common.math.polynomials.GFP32Polynomial;
import de.flexiprovider.common.util.ByteUtils;
import de.flexiprovider.common.util.StringUtils;

/**
 * This Class is used for generating and verifying Signatures according to the
 * LMOTS Signature Scheme defined in the Paper "Asymptotically Efficient
 * Lattice-Based Digital Signatures" by Vadim Lyubashevsky and Daniele
 * Micciancio.
 * <p>
 * See Page 10 and 11 of the Paper for the algorithm step by step.
 * 
 */
public abstract class LMOTSSignature extends Signature {

	/**
	 * LMOTS Signature with RIPEMD128
	 * 
	 */
	public static class RIPEMD128 extends LMOTSSignature {
		/**
		 * Constructor.
		 */
		public RIPEMD128() {
			super(new de.flexiprovider.core.md.RIPEMD128());
		}
	}

	/**
	 * LMOTS Signature with RIPEMD160
	 * 
	 */
	public static class RIPEMD160 extends LMOTSSignature {
		/**
		 * Constructor.
		 */
		public RIPEMD160() {
			super(new de.flexiprovider.core.md.RIPEMD160());
		}
	}

	/**
	 * LMOTS Signature with RIPEMD256
	 * 
	 */
	public static class RIPEMD256 extends LMOTSSignature {
		/**
		 * Constructor.
		 */
		public RIPEMD256() {
			super(new de.flexiprovider.core.md.RIPEMD256());
		}
	}

	/**
	 * LMOTS Signature with RIPEMD320
	 * 
	 */
	public static class RIPEMD320 extends LMOTSSignature {
		/**
		 * Constructor.
		 */
		public RIPEMD320() {
			super(new de.flexiprovider.core.md.RIPEMD320());
		}
	}

	/**
	 * LMOTS Signature with SHA1
	 * 
	 */
	public static class SHA1 extends LMOTSSignature {
		/**
		 * Constructor.
		 */
		public SHA1() {
			super(new de.flexiprovider.core.md.SHA1());
		}
	}

	/**
	 * LMOTS Signature with SHA224
	 * 
	 */
	public static class SHA224 extends LMOTSSignature {
		/**
		 * Constructor.
		 */
		public SHA224() {
			super(new de.flexiprovider.core.md.SHA224());
		}
	}

	/**
	 * LMOTS Signature with SHA256
	 * 
	 */
	public static class SHA256 extends LMOTSSignature {
		/**
		 * Constructor.
		 */
		public SHA256() {
			super(new de.flexiprovider.core.md.SHA256());
		}
	}

	/**
	 * LMOTS Signature with SHA384
	 * 
	 */
	public static class SHA384 extends LMOTSSignature {
		/**
		 * Constructor.
		 */
		public SHA384() {
			super(new de.flexiprovider.core.md.SHA384());
		}
	}

	/**
	 * LMOTS Signature with SHA512
	 * 
	 */
	public static class SHA512 extends LMOTSSignature {
		/**
		 * Constructor.
		 */
		public SHA512() {
			super(new de.flexiprovider.core.md.SHA512());
		}
	}

	/**
	 * LMOTS Signature with any hash function
	 * 
	 */
	public static class GENERIC extends LMOTSSignature {
		/**
		 * Constructor.
		 */
		public GENERIC(MessageDigest md) {
			super(md);
		}
	}

	// parameters defined in the paper
	private int phi;

	private int m;

	private int n;

	private int p;

	private LMOTSPrivateKey privKey;

	private LMOTSPublicKey pubKey;

	private int[] f = null;

	/* messageDigest used to hash the message */
	private MessageDigest md;

	/* message to be signed */
	private byte[] message;

	private GFP32Polynomial msgPoly;

	/* the hash function */
	private LMOTSHash hFunc;

	/**
	 * Constructor.
	 * 
	 * @param md
	 *            the message digest
	 */
	protected LMOTSSignature(MessageDigest md) {
		this.md = md;
	}

	private boolean acceptVerify(Vector vect) {
		return getNorm(vect) <= (10 * phi * (IntegerFunctions.intRoot(p, m))
				* n * IntegerFunctions
				.floatPow(IntegerFunctions.floatLog(n), 2));
	}

	private GFP32Polynomial calcHashedSignature() {
		return pubKey.getHashedK().multiply(msgPoly).add(pubKey.getHashedL());
	}

	private int getNorm(int[] poly) {
		int norm = 0;
		int temp;
		for (int i = poly.length; i > 0; i--) {
			temp = poly[i - 1];
			if (norm < temp) {
				norm = temp;
			}
		}
		return norm;
	}

	private int getNorm(Vector vector) {
		int norm = 0;
		int temp;
		for (int i = 0; i < vector.size(); i++) {
			((GFP32Polynomial) vector.elementAt(i)).compressThis();
		}

		for (int i = vector.size(); i > 0; i--) {
			temp = getNorm(((GFP32Polynomial) vector.elementAt(i - 1))
					.getPoly());
			if (norm < temp) {
				norm = temp;
			}
		}

		return norm;
	}

	public int getSignatureLength() {
		return m * n;
	}

	/**
	 * Hashes the LMOTS Signature as specified in {@link LMOTSSignature}
	 * 
	 * @return Returns the {@link GFP32Polynomial} of the hashed Signature
	 */
	public GFP32Polynomial hashSignature(byte[] signature) {
		Vector sig = new GFPVectorSerial(signature).getVectorRepresentation();
		return hFunc.calculatHash(sig);
	}

	/**
	 * Initialize the signature algorithm for signing a message.
	 * 
	 * @param privKey
	 *            the private key of the signer
	 * @param random
	 *            a source of randomness (not used)
	 * @throws InvalidKeyException
	 *             if the key is not an instance of {@link LMOTSPrivateKey}.
	 */
	public void initSign(PrivateKey privKey, SecureRandom random)
			throws InvalidKeyException {
		if (privKey.getClass().equals(LMOTSPrivateKey.class)) {
			this.privKey = (LMOTSPrivateKey) privKey;
		} else {
			throw new InvalidKeyException();
		}

	}

	/**
	 * Initialize the signature algorithm for verifying a signature.
	 * 
	 * @param pubKey
	 *            the public key of the signer.
	 * @throws InvalidKeyException
	 *             if the public key is not an instance of
	 *             {@link LMOTSPublicKey}.
	 */
	public void initVerify(PublicKey pubKey) throws InvalidKeyException {
		if (pubKey.getClass().equals(LMOTSPublicKey.class)) {
			this.pubKey = (LMOTSPublicKey) pubKey;
			hFunc = ((LMOTSPublicKey) pubKey).getHashFunction();
		} else {
			throw new InvalidKeyException();
		}
	}

	private GFP32Polynomial parseToGFP(byte[] b) {

		if (b == null) {
			return null;
		}

		int[] poly = new int[b.length * 8];
		String bitString = "";
		bitString = ByteUtils.toBinaryString(b);
		bitString = StringUtils.filterSpaces(bitString);

		for (int i = b.length; i > 0; i--) {
			for (int j = 7; j >= 0; j--) {
				poly[i * 8 - j - 1] = bitString.charAt((i - 1) * 8 + j) - 48;

			}
		}

		return new GFP32Polynomial(f, p, poly);
	}

	public void setMessage(byte[] message) {
		msgPoly = parseToGFP(md.digest(message));
		// msgPoly.print();
	}

	/**
	 * Initialize this signature engine with the specified parameter set
	 * 
	 * @param params
	 *            the parameters
	 * @throws InvalidAlgorithmParameterException
	 */
	public void setParameters(AlgorithmParameterSpec params)
			throws InvalidAlgorithmParameterException {

		if (!(params instanceof LMOTSParameterSpec)) {
			throw new InvalidAlgorithmParameterException("Wrong Parameterclass");
		}

		if (params == null) {
			throw new InvalidAlgorithmParameterException(
					"Params cannot be null");
		}

		LMOTSParameterSpec paramSpec = (LMOTSParameterSpec) params;

		phi = paramSpec.getPhi();
		f = paramSpec.getF();

		n = paramSpec.getDegree();
		m = paramSpec.getM();
		p = paramSpec.getP();

		hFunc = paramSpec.getHFunction();

		int mdLength = md.getDigestLength() * 8;
		if (mdLength > n) {
			throw new InvalidAlgorithmParameterException(
					"The Signature Polynomial length must be greater than "
							+ mdLength);
		}

	}

	/**
	 * Sign a message.
	 * 
	 * @return the signature.
	 */
	public byte[] sign() {
		message = md.digest();

		msgPoly = parseToGFP(message);
		// msgPoly.print();

		Vector sM = msgPoly.multiply(privKey.getK());

		Vector result = new Vector();
		Vector l = privKey.getL();
		result.setSize(m);
		for (int i = m - 1; i >= 0; i--) {
			result.setElementAt(((GFP32Polynomial) sM.elementAt(i))
					.add((GFP32Polynomial) l.elementAt(i)), i);
		}

		return new GFPVectorSerial(result).getArrayRepresentation();
	}

	/**
	 * Feed a message byte to the message digest.
	 * 
	 * @param input
	 *            the message byte
	 * 
	 * @throws SignatureException
	 */
	public void update(byte input) {
		md.update(input);
	}

	/**
	 * Feed an array of message bytes to the message digest.
	 * 
	 * @param input
	 *            the array of message bytes
	 * @param inOff
	 *            index of message start
	 * @param inLen
	 *            number of message bytes
	 */
	public void update(byte[] input, int inOff, int inLen) {
		md.update(input, inOff, inLen);
	}

	/**
	 * Verifies the supplied Signature
	 * 
	 * @param signature
	 *            the Signature byte array
	 * @return True if the Signature is valid, false otherwise.
	 * @throws SignatureException
	 *             if the Verification fails
	 */
	public boolean verify(byte[] signature) throws SignatureException {
		if (hashSignature(signature).equals(calcHashedSignature())) {
			Vector signatureVector = new GFPVectorSerial(signature)
					.getVectorRepresentation();
			if (acceptVerify(signatureVector)) {
				return true;
			}
			throw new SignatureException(
					"Verification failed: invalid signature size");
		}
		throw new SignatureException(
				"Verification failed: invalid signature hash");
	}

}
