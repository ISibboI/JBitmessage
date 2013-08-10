package de.flexiprovider.nf.iq.iqdsa;

import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.keys.KeyPair;
import de.flexiprovider.api.keys.KeyPairGenerator;
import de.flexiprovider.api.parameters.AlgorithmParameterGenerator;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.math.quadraticfields.IQClassGroup;
import de.flexiprovider.common.math.quadraticfields.QuadraticIdeal;

/**
 * This class is used to generate key pairs for the IQDSA signature algorithm
 * (implemented by {@link IQDSASignature}.
 * 
 * @author Ralf-P. Weinmann
 */
public class IQDSAKeyPairGenerator extends KeyPairGenerator {

    private IQDSAParameterSpec params;

    private FlexiBigInt discriminant;

    private QuadraticIdeal gamma;

    private IQClassGroup classGroup;

    private SecureRandom random;

    private static final int exponentLength = 400;

    // flag indicating whether the key pair generator has been initialized
    private boolean initialized;

    /**
     * Initialize the IQDSA key pair generator with the specified parameters
     * (supposed to be an instance of {@link IQDSAParameterSpec}) and source of
     * randomness. If no parameters are specified, new parameters are generated
     * for the {@link IQDSAParamGenParameterSpec#DEFAULT_SIZE default size}
     * using the {@link IQDSAParameterGenerator}.
     * 
     * @param params
     *                the parameters
     * @param random
     *                the source of randomness
     * @throws InvalidAlgorithmParameterException
     *                 if the parameters are not an instance of
     *                 {@link IQDSAParameterSpec}.
     */
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
	    throws InvalidAlgorithmParameterException {

	this.random = random != null ? random : Registry.getSecureRandom();

	// if no parameters are specified
	if (params == null) {
	    // generate parameters for the default key size
	    initialize(IQDSAParamGenParameterSpec.DEFAULT_SIZE, this.random);
	}

	if (!(params instanceof IQDSAParameterSpec)) {
	    throw new InvalidAlgorithmParameterException("unsupported type");
	}
	this.params = (IQDSAParameterSpec) params;

	discriminant = this.params.getDiscriminant();
	classGroup = new IQClassGroup(discriminant);
	gamma = this.params.getGamma();

	initialized = true;
    }

    /**
     * Initialize the IQDSA key pair generator for given key size and source of
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
	IQDSAParamGenParameterSpec genParams = new IQDSAParamGenParameterSpec(
		keySize);
	AlgorithmParameterGenerator paramGen = new IQDSAParameterGenerator();
	try {
	    paramGen.init(genParams, this.random);
	    initialize(paramGen.generateParameters(), this.random);
	} catch (InvalidAlgorithmParameterException e) {
	    // the parameters are correct and must be accepted
	    throw new RuntimeException("internal error");
	}
    }

    private void initializeDefault() {
	// generate parameters for the default key size
	initialize(IQDSAParamGenParameterSpec.DEFAULT_SIZE, Registry
		.getSecureRandom());
    }

    /**
     * Generate an IQDSA key pair, consisting of an {@link IQDSAPublicKey} and
     * an {@link IQDSAPrivateKey}.
     * 
     * @return the generated key pair
     */
    public KeyPair genKeyPair() {
	if (!initialized) {
	    initializeDefault();
	}

	// generate a random integer a of fixed bit length
	FlexiBigInt a = new FlexiBigInt(exponentLength, random)
		.setBit(exponentLength - 1);

	// compute alpha = gamma^a
	QuadraticIdeal alpha = classGroup.power(gamma, a);

	IQDSAPublicKey pubKey = new IQDSAPublicKey(params, alpha);
	IQDSAPrivateKey privKey = new IQDSAPrivateKey(params, a);

	return new KeyPair(pubKey, privKey);
    }

}
