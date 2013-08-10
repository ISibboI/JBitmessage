package de.flexiprovider.pqc.ecc.niederreiter;

import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.exceptions.InvalidParameterException;
import de.flexiprovider.api.keys.KeyPair;
import de.flexiprovider.api.keys.KeyPairGenerator;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.math.codingtheory.GF2mField;
import de.flexiprovider.common.math.codingtheory.GoppaCode;
import de.flexiprovider.common.math.codingtheory.PolynomialGF2mSmallM;
import de.flexiprovider.common.math.codingtheory.PolynomialRingGF2m;
import de.flexiprovider.common.math.codingtheory.GoppaCode.MaMaPe;
import de.flexiprovider.common.math.linearalgebra.GF2Matrix;
import de.flexiprovider.common.math.linearalgebra.Permutation;
import de.flexiprovider.pqc.ecc.ECCKeyGenParameterSpec;

/**
 * This class implements key pair generation of the Niederreiter public-key
 * cryptosystem (Niederreiter PKCS). It class extends the
 * {@link KeyPairGenerator} class.
 * <p>
 * Given the parameters m and t or the key size n, the algorithm generates the
 * following matrices:
 * <ul>
 * <li>H' - k x n check matrix of a binary irreducible (n,k) Goppa code GC
 * which can correct up to t errors where n = 2^m and k is chosen maximal</li>
 * <li>S - k x k a random binary non-singular matrix</li>
 * <li>P - n x n a random peremutation matrix</li>
 * </ul>
 * Then, compute the k x n matrix H = SH'P.
 * <p>
 * The public key is (t, n, H), the private key is (m,k,field polynomial,Goppa
 * polynomial,S,P).
 * <p>
 * A key pair consists of a {@link NiederreiterPublicKey} and a
 * {@link NiederreiterPrivateKey}.
 * <p>
 * The default parameters are (m, t) = (11, 50).
 * <p>
 * The Niederreiter key pair generator can be used as follows:
 * <p>
 * 1. get instance of NiederreiterPKC key pair generator:<br/>
 * <tt>KeyPairGenerator kpg =
 * KeyPairGenerator.getInstance("Niederreiter","FlexiPQC");</tt><br/>
 * 2. initialize the KPG with the key size n:<br/> <tt>kpg.initialize(n);</tt><br/>
 * or with the parameters m and t: <br/> <tt>kpg.initialize(m,t);</tt><br/>
 * 3. create McElicePKC key pair:<br/>
 * <tt>KeyPair keyPair = kpg.generateKeyPair();</tt><br/> 4. get the encoded
 * private and public keys from the key pair:<br/>
 * <tt>encodedPublicKey = keyPair.getPublic().getEncoded();<br/>
 * encodedPrivateKey = keyPair.getPrivate().getEncoded();</tt>
 * 
 * @see ECCKeyGenParameterSpec
 * @author Elena Klintsevich
 * @author Martin Döring
 */
public class NiederreiterKeyPairGenerator extends KeyPairGenerator {

    // the extension degree of the finite field GF(2^m)
    private int m;

    // the length of the code
    private int n;

    // the error correction capability
    private int t;

    // the field polynomial
    private int fieldPoly;

    // the source of randomness
    private SecureRandom random;

    // flag indicating whether the key pair generator has been initialized
    private boolean initialized = false;

    /**
     * Initialize the key pair generator with the given parameters and source of
     * randomness. The parameters have to be an instance of
     * {@link ECCKeyGenParameterSpec}. If the parameters are <tt>null</tt>, the
     * default parameters are used (see {@link ECCKeyGenParameterSpec}).
     * 
     * @param params
     *                the parameters
     * @param random
     *                the source of randomness
     * @throws InvalidAlgorithmParameterException
     *                 if the parameters are not an instance of
     *                 {@link ECCKeyGenParameterSpec}.
     */
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
	    throws InvalidAlgorithmParameterException {

	this.random = (random != null) ? random : Registry.getSecureRandom();

	if (params == null) {
	    initializeDefault();
	    return;
	}

	if (!(params instanceof ECCKeyGenParameterSpec)) {
	    throw new InvalidAlgorithmParameterException("unsupported type");
	}
	ECCKeyGenParameterSpec mParams = (ECCKeyGenParameterSpec) params;

	m = mParams.getM();
	n = mParams.getN();
	t = mParams.getT();
	fieldPoly = mParams.getFieldPoly();

	initialized = true;
    }

    /**
     * Initialize the key pair generator.
     * 
     * @param keySize
     *                the length of the code
     * @param random
     *                the source of randomness
     */
    public void initialize(int keySize, SecureRandom random) {
	try {
	    ECCKeyGenParameterSpec paramSpec = new ECCKeyGenParameterSpec(keySize);
	    initialize(paramSpec, random);
	} catch (InvalidParameterException e) {
	    throw new RuntimeException("invalid key size");
	} catch (InvalidAlgorithmParameterException e) {
	    // the parameters are correct and must be accepted
	    throw new RuntimeException("internal error");
	}
    }

    /**
     * Default initialization of the key pair generator.
     */
    private void initializeDefault() {
	try {
	    ECCKeyGenParameterSpec paramSpec = new ECCKeyGenParameterSpec();
	    initialize(paramSpec, Registry.getSecureRandom());
	} catch (InvalidAlgorithmParameterException e) {
	    // the parameters are correct and must be accepted
	    throw new RuntimeException("internal error");
	}
    }

    /**
     * Generate a key pair.
     * 
     * @return the key pair, consisting of a {@link NiederreiterPrivateKey} and
     *         a {@link NiederreiterPublicKey}.
     * @see NiederreiterPrivateKey
     * @see NiederreiterPublicKey
     */
    public KeyPair genKeyPair() {
	if (!initialized) {
	    initializeDefault();
	}

	// finite field GF(2^m)
	GF2mField field = new GF2mField(m, fieldPoly);

	// generate Goppa polynomial
	PolynomialGF2mSmallM gp = new PolynomialGF2mSmallM(field, t,
		PolynomialGF2mSmallM.RANDOM_IRREDUCIBLE_POLYNOMIAL, random);

	// polynomial ring used to compute square root matrix
	PolynomialRingGF2m ring = new PolynomialRingGF2m(field, gp);
	// the matrix used to compute square roots
	PolynomialGF2mSmallM[] qInv = ring.getSquareRootMatrix();

	// generate canonical check matrix H
	GF2Matrix h = GoppaCode.createCanonicalCheckMatrix(field, gp);
	int k = h.getNumRows();

	// generate matrices S^-1, M, and a permutation P satisfying
	// S*H*P=(Id|M)
	MaMaPe mmp = GoppaCode.computeSystematicForm(h, random);
	GF2Matrix sInv = mmp.getFirstMatrix();
	GF2Matrix matrixM = mmp.getSecondMatrix();
	Permutation p = mmp.getPermutation();

	NiederreiterPublicKey pubKey = new NiederreiterPublicKey(n, t, matrixM);
	NiederreiterPrivateKey privKey = new NiederreiterPrivateKey(m, k,
		field, gp, qInv, sInv, p);

	return new KeyPair(pubKey, privKey);
    }
}
