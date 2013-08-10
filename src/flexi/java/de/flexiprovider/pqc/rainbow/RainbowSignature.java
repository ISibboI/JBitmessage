package de.flexiprovider.pqc.rainbow;

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
import de.flexiprovider.pqc.rainbow.util.ComputeInField;
import de.flexiprovider.pqc.rainbow.util.GF2Field;

/**
 * This class extends the Signature-class of the FlexiProvider-Api.
 * 
 * It implements the sign and verify functions for the Rainbow Signature Scheme.
 * Here the message, which has to be signed, is updated and hashed. The use of
 * different hash functions is possible.
 * 
 * Detailed information about the signature and the verify-method is to be found
 * in the paper of Jintai Ding, Dieter Schmidt: Rainbow, a New Multivariable
 * Polynomial Signature Scheme. ACNS 2005: 164-175
 * (http://dx.doi.org/10.1007/11496137_12)
 * 
 * @author Patrick Neugebauer
 * @author Marius Senftleben
 * @author Tsvetoslava Vateva
 * 
 */
public class RainbowSignature extends Signature {

	// The OID of Rainbow. x.y.z must be set
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.5.2";

	// private key
	private RainbowPrivateKey privKey;

	// public key
	private RainbowPublicKey pubKey;

	// source of randomness
	private SecureRandom random;

	// the message digest
	private MessageDigest[] mds;

	// rainbow parameters
	RainbowParameterSpec rainbowParams; // not really needed

	// the length of a document that can be signed with the privKey
	int signableDocumentLength;
	
	//digest length of concatenated hash functions
	int numOfHashBytes;

	// container for the oil and vinegar variables of all the layers
	private short[] x;
	private ComputeInField cf = new ComputeInField();

	/**
	 * Rainbow Signature Scheme using the following hashfunctions in descending
	 * priority:
	 * 
	 * @see de.flexiprovider.core.md.SHA512
	 * @see de.flexiprovider.core.md.SHA384
	 * @see de.flexiprovider.core.md.SHA256
	 * @see de.flexiprovider.core.md.SHA224
	 * @see de.flexiprovider.core.md.SHA1
	 * @see de.flexiprovider.core.md.RIPEMD320
	 * @see de.flexiprovider.core.md.RIPEMD256
	 * @see de.flexiprovider.core.md.RIPEMD160
	 * @see de.flexiprovider.core.md.RIPEMD128
	 * @see de.flexiprovider.core.md.MD5
	 * 
	 */
	public RainbowSignature() {
		int i = 0;
		// mds[0] : highest priority, mds[last] : lowest prio
		mds = new MessageDigest[10];
		mds[i++] = new de.flexiprovider.core.md.SHA512();
		mds[i++] = new de.flexiprovider.core.md.SHA384();
		mds[i++] = new de.flexiprovider.core.md.SHA256();
		mds[i++] = new de.flexiprovider.core.md.SHA224();
		mds[i++] = new de.flexiprovider.core.md.SHA1();
		mds[i++] = new de.flexiprovider.core.md.RIPEMD320();
		mds[i++] = new de.flexiprovider.core.md.RIPEMD256();
		mds[i++] = new de.flexiprovider.core.md.RIPEMD160();
		mds[i++] = new de.flexiprovider.core.md.RIPEMD128();
		mds[i++] = new de.flexiprovider.core.md.MD5();
		
		// determine digest length of concatenated hash functions
		numOfHashBytes = 0;
		for (int h = 0; h < mds.length; h++) {
			numOfHashBytes += mds[h].getDigestLength();
		}
	}

	/**
	 * Initializes the signature algorithm for signing a message.
	 * 
	 * @param privateKey
	 *            the private key of the signature
	 * @param random
	 *            the source of randomness
	 * @throws InvalidKeyException
	 *             if the key is not an instance of RSAPrivateKey or
	 *             RSAPrivateCrtKey.
	 */
	public void initSign(PrivateKey privateKey, SecureRandom random)
			throws InvalidKeyException {
		// checks privKey instance
		if (!(privateKey instanceof RainbowPrivateKey)) {
			throw new InvalidKeyException(
					"key is not an instance of RainbowPrivateKey");
		}
		// makes sure that a source of randomness exists
		if (random != null) {
			this.random = random;
		} else {
			this.random = Registry.getSecureRandom();
		}
		// sets rainbow priv key
		privKey = (RainbowPrivateKey) privateKey;
		int vi[] = privKey.getVi();
		this.signableDocumentLength = vi[vi.length - 1] - vi[0];
	}

	/**
	 * Initializes the signature algorithm for verifying a message.
	 * 
	 * @param pubKey
	 *            public key of signer
	 * @throws InvalidKeyException
	 *             if the key is not an instance of RainbowPublicKey
	 */
	public void initVerify(PublicKey publicKey) throws InvalidKeyException {
		if (!(publicKey instanceof RainbowPublicKey)) {
			throw new InvalidKeyException(
					"key is not an instance of RainbowPublicKey");
		}
		this.pubKey = (RainbowPublicKey) publicKey;
		this.signableDocumentLength = this.pubKey.getDocLength();
	}

	/**
	 * Initializes this signature engine with the specified parameter set.
	 * 
	 * @param params
	 *            the parameters
	 * @throws InvalidAlgorithmParameterException. if the given parameters are
	 *         inappropriate for this signature engine.
	 */
	public void setParameters(AlgorithmParameterSpec params)
			throws InvalidAlgorithmParameterException {
	}

	/**
	 * Passes a message byte to the message digest.
	 * 
	 * @param b
	 *            the message byte.
	 */
	public void update(byte input) throws SignatureException {
		for (int i = 0; i < mds.length; i++) {
			mds[i].update(input);
		}
	}

	/**
	 * Passes message bytes to the message digest.
	 * 
	 * @param b
	 *            the message bytes.
	 * @param offset
	 *            the index where the message bytes starts.
	 * @param length
	 *            the number of message bytes.
	 */
	public void update(byte[] input, int inOff, int inLen)
			throws SignatureException {
		for (int i = 0; i < mds.length; i++) {
			mds[i].update(input, inOff, inLen);
		}
	}

	/**
	 * initial operations before solving the Linear equation system.
	 * 
	 * @param layer
	 *            the current layer for which a LES is to be solved.
	 * @param msg
	 *            the message that should be signed.
	 * @return Y_ the modified document needed for solving LES, (Y_ =
	 *         A1^{-1}*(Y-b1)) linear map L1 = A1 x + b1.
	 */
	private short[] initSign(Layer[] layer, short[] msg) {

		/* preparation: Modifies the document with the inverse of L1 */
		// tmp = Y - b1:
		short[] tmpVec = new short[msg.length];
		tmpVec = cf.addVect(privKey.getb1(), msg);

		// Y_ = A1^{-1} * (Y - b1) :
		short[] Y_ = cf.multiplyMatrix(privKey.getA1inv(), tmpVec);

		/* generates the vinegar vars of the first layer at random */
		for (int i = 0; i < layer[0].getVi(); i++) {
			x[i] = (short) random.nextInt();
			x[i] = (short) (x[i] & GF2Field.MASK);
		}

		return Y_;
	}

	/**
	 * This function signs the message that has been updated, making use of the
	 * private key.
	 * 
	 * For computing the signature, L1 and L2 are needed, as well as LES should
	 * be solved for each layer in order to find the Oil-variables in the layer.
	 * 
	 * The Vinegar-variables of the first layer are random generated.
	 * 
	 * @return the signature of the message.
	 */
	public byte[] sign() throws SignatureException {

		Layer[] layer = this.privKey.getLayers();
		int numberOfLayers = layer.length;
		x = new short[this.privKey.getA2inv().length]; // all variables

		short[] Y_; // modified document
		short[] y_i; // part of Y_ each polynomial
		int counter; // index of the current part of the doc

		short[] solVec; // the solution of LES pro layer
		short[] tmpVec;

		// the signature as an array of shorts:
		short[] signature;
		// the signature as a byte-array:
		byte[] S = new byte[layer[numberOfLayers - 1].getViNext()];

		// the hashed message msg:
		short[] msg = makeMessageRepresentative();

		// shows if an exception is caught
		boolean ok;
		do {
			ok = true;
			counter = 0;
			try {
				Y_ = initSign(layer, msg);

				for (int i = 0; i < numberOfLayers; i++) {

					y_i = new short[layer[i].getOi()];
					solVec = new short[layer[i].getOi()]; // solution of LES

					/* copy oi elements of Y_ into y_i */
					for (int k = 0; k < layer[i].getOi(); k++) {
						y_i[k] = Y_[counter];
						counter++; // current index of Y_
					}

					/*
					 * plug in the vars of the previous layer in order to get
					 * the vars of the current layer
					 */
					solVec = cf.solveEquation(layer[i].plugInVinegars(x), y_i);

					if (solVec == null) { // LES is not solveable
						throw new SignatureException("LES is not solveable!");
					}

					/* copy the new vars into the x-array */
					for (int j = 0; j < solVec.length; j++) {
						x[layer[i].getVi() + j] = solVec[j];
					}
				}

				/* apply the inverse of L2: (signature = A2^{-1}*(b2+x)) */
				tmpVec = cf.addVect(privKey.getb2(), x);
				signature = cf.multiplyMatrix(privKey.getA2inv(), tmpVec);

				/* cast signature from short[] to byte[] */
				for (int i = 0; i < S.length; i++) {
					S[i] = ((byte) signature[i]);
				}
			} catch (SignatureException se) {
				// if one of the LESs was not solveable - sign again
				ok = false;
			}
		} while (!ok);
		/* return the signature in bytes */
		return S;
	}

	/**
	 * This function verifies the signature of the message that has been
	 * updated, with the aid of the public key.
	 * 
	 * @param the
	 *            signature of the message is given as a byte array.
	 * 
	 * @return true if the signature has been verified, false otherwise.
	 */
	public boolean verify(byte[] signature) throws SignatureException {
		short[] sigInt = new short[signature.length];
		short tmp;

		// convert signature bytes to short[]
		for (int i = 0; i < signature.length; i++) {
			tmp = (short) signature[i];
			tmp &= (short) 0xff;
			sigInt[i] = tmp;
		}

		// hash the document
		short[] msg = makeMessageRepresentative();

		// verify
		short[] verificationResult = verifySignature(sigInt);

		// compare
		boolean verified = true;
		if (msg.length != verificationResult.length) {
			return false;
		}
		for (int i = 0; i < msg.length; i++) {
			verified = verified && msg[i] == verificationResult[i];
		}

		return verified;
	}

	/**
	 * Signature verification using public key
	 * 
	 * @param signature
	 *            vector of dimension n
	 * @return document hash of length n - v1
	 */
	private short[] verifySignature(short[] signature) {

		short[][] coeff_quadratic = pubKey.getCoeffquadratic();
		short[][] coeff_singular = pubKey.getCoeffsingular();
		short[] coeff_scalar = pubKey.getCoeffscalar();

		short[] rslt = new short[coeff_quadratic.length];// n - v1
		int n = coeff_singular[0].length;
		int offset = 0; // array position
		short tmp = 0; // for scalar

		for (int p = 0; p < coeff_quadratic.length; p++) { // no of polynomials
			offset = 0;
			for (int x = 0; x < n; x++) {
				// calculate quadratic terms
				for (int y = x; y < n; y++) {
					tmp = GF2Field.multElem(coeff_quadratic[p][offset],
							GF2Field.multElem(signature[x], signature[y]));
					rslt[p] = GF2Field.addElem(rslt[p], tmp);
					offset++;
				}
				// calculate singular terms
				tmp = GF2Field.multElem(coeff_singular[p][x], signature[x]);
				rslt[p] = GF2Field.addElem(rslt[p], tmp);
			}
			// add scalar
			rslt[p] = GF2Field.addElem(rslt[p], coeff_scalar[p]);
		}

		return rslt;
	}

	/**
	 * This function creates the representative of the message which gets signed
	 * or verified.
	 * 
	 * The Hashvalue H of the document we got is the concatenation of all
	 * hashfunctions used (H = H1 || H2 || ... || Hn).
	 * 
	 * @return message representative
	 */
	private short[] makeMessageRepresentative() {
		// make sure that we have enough hash bytes to sign the desired message
		if (this.numOfHashBytes < this.signableDocumentLength) {
			throw new RuntimeException(
					"Rainbow can't sign the message of that length");
		}

		// contains the hash values of the document we got
		// hashValue[hashFunc][hashValBytes]
		byte[][] hashVals = new byte[mds.length][];

		// the message representative
		short[] msg = new short[this.signableDocumentLength];

		// get hashvalues (digests) of document
		for (int i = 0; i < mds.length; i++) {
			hashVals[i] = mds[i].digest();
		}

		// copy appropriate digest bytes into message byte array

		int h = 0; // hash function counter
		int hbyte = 0; // byte index of hash value
		int i = 0; // message byte counter
		do {
		    
			if (hbyte >= hashVals[h].length) {
				// choose next hashValue from next hash function
				hbyte = 0;
				h++;
			}
			msg[i] = (short) hashVals[h][hbyte];
			msg[i] &= (short) 0xff;
			hbyte++;
			i++;
		} while (i < msg.length);

		return msg;
	}

}
