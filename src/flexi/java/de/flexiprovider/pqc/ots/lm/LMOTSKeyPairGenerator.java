package de.flexiprovider.pqc.ots.lm;

import java.util.Vector;

import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.keys.KeyPair;
import de.flexiprovider.api.keys.KeyPairGenerator;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.math.IntegerFunctions;
import de.flexiprovider.common.math.polynomials.GFP32Polynomial;

/**
 * This class generates the public- and the private key pairs. It randomly and
 * uniformly chooses the private key pair and calculates the public key pair as
 * the hash of the private keys.
 * 
 * @author rob
 * 
 */
public class LMOTSKeyPairGenerator extends KeyPairGenerator {

	private int pos;

	// degree of the polynomial
	private int degree;
	private int m;
	private int p;
	private int phi;
	private int[] f;

	// the hashFunction used to calculate the public-keys
	private LMOTSHash hFunction;

	/**
	 * this method generates a new vector of size m with polynomials
	 * {@link GFP32Polynomial} in it, where the infinite norm is less than
	 * limit.
	 * 
	 * @param limit
	 * @return a vector of polynomials
	 */
	private Vector generateMPoly(int limit) {
		GFP32Polynomial gfp = new GFP32Polynomial(f, p, Registry
				.getSecureRandom());
		Vector v = new Vector();
		for (int i = m; i > 0; i--) {
			v.addElement(gfp.generatePoly(limit));
		}
		return v;
	}

	/**
	 * Generates an LMOTS key pair, consisting of an {@link LMOTSPublicKey} and
	 * an {@link LMOTSPrivateKey}.
	 * 
	 * @return the generated key pair
	 */
	public KeyPair genKeyPair() {

		// STEP 4:
		int length = (int) Math.floor(IntegerFunctions.floatPow(
				IntegerFunctions.floatLog(degree), 2));

		String r = genRndString(length);
		pos = r.indexOf("1") + 1 + length - r.length();

		if (pos == 0) {
			pos = length;
		}

		// STEP 2:
		LMOTSPrivateKey privKey = new LMOTSPrivateKey(pickK(), pickL());

		LMOTSPublicKey pubKey = new LMOTSPublicKey(hFunction, hFunction
				.calculatHash(privKey.getK()), hFunction.calculatHash(privKey
				.getL()));

		return new KeyPair(pubKey, privKey);
	}

	private String genRndString(int len) {
		SecureRandom generator = Registry.getSecureRandom();

		int bound = IntegerFunctions.pow(2, len) - 1;
		String result = "";

		result = Integer.toBinaryString(generator.nextInt(bound));

		return result;
	}

	/**
	 * Initialize the key pair generator.
	 * 
	 * @param params
	 *            the parameters
	 * @param javaRand
	 *            the source of randomness
	 * @throws InvalidAlgorithmParameterException
	 *             if the parameters are not an instance of
	 *             {@link LMOTSParameterSpec}.
	 */
	public void initialize(AlgorithmParameterSpec params,
			de.flexiprovider.api.SecureRandom javaRand)
			throws InvalidAlgorithmParameterException {

		LMOTSParameterSpec paramSpec = (LMOTSParameterSpec) params;

		degree = paramSpec.getDegree();
		f = paramSpec.getF();
		m = paramSpec.getM();
		p = paramSpec.getP();
		phi = paramSpec.getPhi();

		paramSpec.setHFunction(generateMPoly(p));
		hFunction = paramSpec.getHFunction();

	}

	/**
	 * (NOT USED! SEE {@link LMOTSParameterSpec}) Initialize the key pair
	 * generator with the given seed size and source of randomness.
	 * 
	 * @param keysize
	 *            the seed size in bits
	 * @param javaRand
	 *            the source of randomness
	 */
	public void initialize(int keysize,
			de.flexiprovider.api.SecureRandom javaRand) {
		// not used (see javadoc)
	}

	private Vector pickK() {
		int limit = (int) Math.ceil(5 * pos * IntegerFunctions.intRoot(p, m));

		Vector result = generateMPoly(limit);

		return result;
	}

	private Vector pickL() {
		int limit = (int) Math.ceil(5 * pos * degree * phi
				* IntegerFunctions.intRoot(p, m));

		Vector result = generateMPoly(limit);

		return result;
	}

}
