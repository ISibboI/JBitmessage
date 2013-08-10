package de.flexiprovider.core.rsa;

import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.math.FlexiBigInt;

/**
 * This class specifies parameters used by the {@link RSAKeyPairGenerator}.
 * 
 * @author Martin Döring
 */
public class RSAKeyGenParameterSpec extends
	java.security.spec.RSAKeyGenParameterSpec implements
	AlgorithmParameterSpec {

    /**
     * The default key size (1024 bits)
     */
    public static final int DEFAULT_KEY_SIZE = 1024;

    /**
     * The default public exponent (<tt>2<sup>16</sup>+1</tt>)
     */
    public static final FlexiBigInt DEFAULT_EXPONENT = new FlexiBigInt(F4);

    /**
     * Construct the default RSA key generation parameters. The key size is set
     * to the {@link #DEFAULT_KEY_SIZE}, the public exponent is set to the
     * {@link #DEFAULT_EXPONENT}.
     */
    public RSAKeyGenParameterSpec() {
	this(DEFAULT_KEY_SIZE, DEFAULT_EXPONENT);
    }

    /**
     * Construct new RSA key generation parameters from the given key size. The
     * public exponent is set to the {@link #DEFAULT_EXPONENT}. If the key size
     * is invalid, choose the {@link #DEFAULT_KEY_SIZE}.
     * 
     * @param keySize
     *                the key size (&gt;= 512 bits)
     */
    public RSAKeyGenParameterSpec(int keySize) {
	this(keySize, DEFAULT_EXPONENT);
    }

    /**
     * Construct new RSA key generation parameters from the given key size and
     * public exponent. If the key size is invalid, choose the
     * {@link #DEFAULT_KEY_SIZE}. If the public exponent is invalid, choose the
     * {@link #DEFAULT_EXPONENT}.
     * 
     * @param keySize
     *                the key size (&gt;= 512 bits)
     * @param e
     *                the public exponent (must be odd)
     */
    public RSAKeyGenParameterSpec(int keySize, FlexiBigInt e) {
	super(keySize, e.bigInt);
    }

    /**
     * Return the key size in bits. If the key size is &lt; 512, return the
     * {@link #DEFAULT_KEY_SIZE default key size}.
     * 
     * @return the key size in bits
     */
    public int getKeySize() {
	int keySize = getKeysize();
	// check is key size is too small
	if (keySize < 512) {
	    // in this case, return the default key size
	    return DEFAULT_KEY_SIZE;
	}

	// else return the stored key size
	return keySize;
    }

    /**
     * Return the public exponent. If the public exponent is even, return the
     * {@link #DEFAULT_EXPONENT default exponent}.
     * 
     * @return the public exponent
     */
    public FlexiBigInt getE() {
	FlexiBigInt e = new FlexiBigInt(getPublicExponent());
	// check if e is an even number, which is not allowed
	if (!e.testBit(0)) {
	    // in this case, return the default exponent
	    return DEFAULT_EXPONENT;
	}

	// else return the stored exponent
	return e;
    }

}
