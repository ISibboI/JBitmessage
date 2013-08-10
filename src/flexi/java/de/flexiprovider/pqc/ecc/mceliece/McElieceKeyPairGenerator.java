package de.flexiprovider.pqc.ecc.mceliece;

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
 * This class implements key pair generation of the McEliece Public Key
 * Cryptosystem (McEliecePKC). The class extends the <a
 * href="java.security.spec.KeyPairGeneratorSpi">KeyPairGeneratorSpi</a> class.
 * <p>
 * The algorithm is given the parameters m and t or the key size n as input.
 * Then, the following matrices are generated:
 * <ul>
 * <li>G' is a k x n generator matrix of a binary irreducible (n,k) Goppa code
 * GC which can correct up to t errors where n = 2^m and k is chosen maximal,
 * i.e. k <= n - mt</li>
 * <li>H is an mt x n check matrix of the Goppa code GC</li>
 * <li>S is a k x k random binary non-singular matrix</li>
 * <li>P is an n x n random permutation matrix.</li>
 * </ul>
 * Then, the algorithm computes the k x n matrix G = SG'P.<br/> The public key
 * is (n, t, G). The private key is (m, k, field polynomial, Goppa polynomial,
 * H, S, P, setJ);<br/> A key pair consists of a McEliecePublicKey and a
 * McEliecePrivatKey.
 * <p>
 * The default parameters are m = 10 and t = 50.
 * <p>
 * The McElieceKeyPairGenerator can be used as follows:
 * <ol>
 * <li>get instance of McEliecePKC key pair generator:<br/>
 * <tt>KeyPairGenerator kpg =
 * KeyPairGenerator.getInstance("McEliece","FlexiPQC");</tt></li>
 * <li>initialize the KPG with key size n:<br/> <tt>kpg.initialize(n);</tt><br/>
 * or with parameters m and t via a <a
 * href="de.flexiprovider.pqc.ecc.mceliece.McElieceParameterSpec">McElieceParameterSpec</a>:<br/>
 * <tt>McElieceParameterSpec paramSpec = new McElieceParameterSpec(m, t);<br/>
 * kpg.initialize(paramSpec, Registry.getSecureRandom());</tt></li>
 * <li>create McEliecePKC key pair:<br/>
 * <tt>KeyPair keyPair = kpg.generateKeyPair();</tt></li>
 * <li>get the encoded private and public keys from the key pair:<br/>
 * <tt>encodedPublicKey = keyPair.getPublic().getEncoded();<br/>
 * encodedPrivateKey = keyPair.getPrivate().getEncoded();</tt></li>
 * </ol>
 * 
 * @see ECCKeyGenParameterSpec
 * @author Elena Klintsevich
 * @author Martin Döring
 */
public class McElieceKeyPairGenerator extends KeyPairGenerator {

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
     * Initialize the key pair generator with the given key size and source of
     * randomness.
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
     * Generate a McEliece key pair. The public key is an instance of
     * {@link McEliecePublicKey}, the private key is an instance of
     * {@link McEliecePrivateKey}.
     * 
     * @return the McEliece key pair
     * @see McEliecePublicKey
     * @see McEliecePrivateKey
     */
    public KeyPair genKeyPair() {

	if (!initialized) {
	    initializeDefault();
	}

	// finite field GF(2^m)
	GF2mField field = new GF2mField(m, fieldPoly);

	// irreducible Goppa polynomial
	PolynomialGF2mSmallM gp = new PolynomialGF2mSmallM(field, t,
		PolynomialGF2mSmallM.RANDOM_IRREDUCIBLE_POLYNOMIAL, random);
	PolynomialRingGF2m ring = new PolynomialRingGF2m(field, gp);

	// matrix used to compute square roots in (GF(2^m))^t
	PolynomialGF2mSmallM[] sqRootMatrix = ring.getSquareRootMatrix();

	// generate canonical check matrix
	GF2Matrix h = GoppaCode.createCanonicalCheckMatrix(field, gp);

	// compute short systematic form of check matrix
	MaMaPe mmp = GoppaCode.computeSystematicForm(h, random);
	GF2Matrix shortH = mmp.getSecondMatrix();
	Permutation p1 = mmp.getPermutation();

	// compute short systematic form of generator matrix
	GF2Matrix shortG = (GF2Matrix) shortH.computeTranspose();

	// extend to full systematic form
	GF2Matrix gPrime = shortG.extendLeftCompactForm();

	// obtain number of rows of G (= dimension of the code)
	int k = shortG.getNumRows();

	// generate random invertible (k x k)-matrix S and its inverse S^-1
	GF2Matrix[] matrixSandInverse = GF2Matrix
		.createRandomRegularMatrixAndItsInverse(k, random);

	// generate random permutation P2
	Permutation p2 = new Permutation(n, random);

	// compute public matrix G=S*G'*P2
	GF2Matrix g = (GF2Matrix) matrixSandInverse[0].rightMultiply(gPrime);
	g = (GF2Matrix) g.rightMultiply(p2);

	// generate keys
	McEliecePublicKey pubKey = new McEliecePublicKey(n, t, g);
	McEliecePrivateKey privKey = new McEliecePrivateKey(n, k, field, gp,
		matrixSandInverse[1], p1, p2, h, sqRootMatrix);

	// return key pair
	return new KeyPair(pubKey, privKey);
    }

}
