package de.flexiprovider.nf.iq.iqgq;

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
 * This class is used to generate key pairs for the IQGQ signature algorithm
 * (implemented by {@link IQGQSignature}.
 * 
 * @author Ralf-P. Weinmann
 */
public class IQGQKeyPairGenerator extends KeyPairGenerator {

    private IQGQParameterSpec params;

    private FlexiBigInt discriminant;

    private IQClassGroup classGroup;

    private SecureRandom random;

    private static final int exponentLength = 200;

    // flag indicating whether the key pair generator has been initialized
    private boolean initialized;

    /**
     * Initialize the IQGQ key pair generator with the specified parameters
     * (supposed to be an instance of {@link IQGQParameterSpec}) and source of
     * randomness. If no parameters are specified, new parameters are generated
     * for the {@link IQGQParamGenParameterSpec#DEFAULT_SIZE default size} using
     * the {@link IQGQParameterGenerator}.
     * 
     * @param params
     *                the parameters
     * @param random
     *                the source of randomness
     * @throws InvalidAlgorithmParameterException
     *                 if the parameters are not an instance of
     *                 {@link IQGQParameterSpec}.
     */
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
	    throws InvalidAlgorithmParameterException {

	this.random = random != null ? random : Registry.getSecureRandom();

	// if no parameters are specified
	if (params == null) {
	    // generate parameters for the default key size
	    initialize(IQGQParamGenParameterSpec.DEFAULT_SIZE, this.random);
	}

	if (!(params instanceof IQGQParameterSpec)) {
	    throw new InvalidAlgorithmParameterException("unsupported type");
	}
	this.params = (IQGQParameterSpec) params;

	discriminant = this.params.getDiscriminant();
	classGroup = new IQClassGroup(discriminant);

	initialized = true;
    }

    /**
     * Initialize the IQGQ key pair generator for given key size and source of
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
	IQGQParamGenParameterSpec genParams = new IQGQParamGenParameterSpec(
		keySize);
	AlgorithmParameterGenerator paramGenerator = new IQGQParameterGenerator();
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
	initialize(IQGQParamGenParameterSpec.DEFAULT_SIZE, Registry
		.getSecureRandom());
    }

    /**
     * Generate an IQGQ key pair, consisting of an {@link IQGQPublicKey} and an
     * {@link IQGQPrivateKey}.
     * 
     * @return the generated key pair
     */
    public KeyPair genKeyPair() {
	if (!initialized) {
	    initializeDefault();
	}

	// generate a random exponent
	FlexiBigInt exponent = new FlexiBigInt(discriminant.bitLength() - 1,
		20, random);

	// randomly pick a prime ideal alpha of the class group
	QuadraticIdeal alpha = classGroup.randomPrimePowerIdeal(exponentLength,
		1);

	// compute theta = alpha^(-exponent)
	QuadraticIdeal theta = classGroup.invert(classGroup.power(alpha,
		exponent));

	IQGQPublicKey pubKey = new IQGQPublicKey(params, theta, exponent);
	IQGQPrivateKey privKey = new IQGQPrivateKey(params, alpha, exponent);

	return new KeyPair(pubKey, privKey);
    }

}
