package de.flexiprovider.nf.iq.iqrdsa;

import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.keys.KeyPair;
import de.flexiprovider.api.keys.KeyPairGenerator;
import de.flexiprovider.api.parameters.AlgorithmParameterGenerator;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.math.IntegerFunctions;
import de.flexiprovider.common.math.quadraticfields.IQClassGroup;
import de.flexiprovider.common.math.quadraticfields.QuadraticIdeal;

/**
 * This class is used to generate key pairs for the IQRDSA signature algorithm
 * (implemented by {@link IQRDSASignature}.
 * 
 * @author Ralf-P. Weinmann
 */
public class IQRDSAKeyPairGenerator extends KeyPairGenerator {

    private IQRDSAParameterSpec params;

    private FlexiBigInt discriminant;

    private FlexiBigInt modulus;

    private IQClassGroup classGroup;

    private SecureRandom random;

    // flag indicating whether the key pair generator has been initialized
    private boolean initialized;

    /**
     * Initialize the IQRDSA key pair generator with the specified parameters
     * (supposed to be an instance of {@link IQRDSAParameterSpec}) and source
     * of randomness. If no parameters are specified, new parameters are
     * generated for the
     * {@link IQRDSAParamGenParameterSpec#DEFAULT_SIZE default size} using the
     * {@link IQRDSAParameterGenerator}.
     * 
     * @param params
     *                the parameters
     * @param random
     *                the source of randomness
     * @throws InvalidAlgorithmParameterException
     *                 if the parameters are not an instance of
     *                 {@link IQRDSAParameterSpec}.
     */
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
	    throws InvalidAlgorithmParameterException {

	this.random = random != null ? random : Registry.getSecureRandom();

	// if no parameters are specified
	if (params == null) {
	    // generate parameters for the default key size
	    initialize(IQRDSAParamGenParameterSpec.DEFAULT_SIZE, this.random);
	}

	if (!(params instanceof IQRDSAParameterSpec)) {
	    throw new InvalidAlgorithmParameterException("unsupported type");
	}
	this.params = (IQRDSAParameterSpec) params;

	discriminant = this.params.getDiscriminant();
	classGroup = new IQClassGroup(discriminant);
	modulus = this.params.getModulus();

	initialized = true;
    }

    /**
     * Initialize the IQRDSA key pair generator for given key size and source of
     * randomness. The key size is the bit length of the discriminant of the
     * class group.
     * 
     * @param keySize
     *                the bit length of the discriminant of the class group
     * @param random
     *                the source of randomness
     */
    public void initialize(int keySize, SecureRandom random) {
	this.random = random != null ? random : Registry.getSecureRandom();

	// generate parameters for the chosen key size
	IQRDSAParamGenParameterSpec genParams = new IQRDSAParamGenParameterSpec(
		keySize);
	AlgorithmParameterGenerator paramGenerator = new IQRDSAParameterGenerator();
	try {
	    paramGenerator.init(genParams, this.random);
	    initialize(paramGenerator.generateParameters(), this.random);
	} catch (InvalidAlgorithmParameterException e) {
	    // the parameters are correct and must be accepted
	    throw new RuntimeException("internal error");
	}
    }

    private void initializeDefault() {
	// generate parameters for the default key size
	initialize(IQRDSAParamGenParameterSpec.DEFAULT_SIZE, Registry
		.getSecureRandom());
    }

    /**
     * Generate an IQRDSA key pair, consisting of an {@link IQRDSAPublicKey} and
     * an {@link IQRDSAPrivateKey}.
     * 
     * @return the generated key pair
     */
    public KeyPair genKeyPair() {
	if (!initialized) {
	    initializeDefault();
	}

	// randomly pick an element gamma of the class group
	QuadraticIdeal gamma = classGroup.randomIdeal();

	// choose a random number a in the interval [2, p-2]
	FlexiBigInt a = IntegerFunctions.randomize(
		modulus.subtract(FlexiBigInt.valueOf(2)), random).add(
		FlexiBigInt.valueOf(2));

	// compute alpha = gamma^a
	QuadraticIdeal alpha = classGroup.power(gamma, a);

	IQRDSAPublicKey pubKey = new IQRDSAPublicKey(params, gamma, alpha);
	IQRDSAPrivateKey privKey = new IQRDSAPrivateKey(params, gamma, alpha, a);

	return new KeyPair(pubKey, privKey);
    }

}
