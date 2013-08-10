package de.flexiprovider.core.mprsa;

import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.core.rsa.RSAKeyGenParameterSpec;

/**
 * This class specifies parameters used by the {@link MpRSAKeyPairGenerator}.
 * 
 * @author Paul Nguentcheu
 * @author Martin Döring
 */
public class MpRSAKeyGenParameterSpec extends RSAKeyGenParameterSpec implements
	AlgorithmParameterSpec {

    /**
     * The default number of primes
     */
    public static final int DEFAULT_NUM_PRIMES = 3;

    // the number of primes
    private int k;

    /**
     * Construct the default MeRSA key generation parameters. Choose the key
     * size as {@link #DEFAULT_KEY_SIZE}, the public exponent as
     * {@link #DEFAULT_EXPONENT}, and the exponent of the prime <tt>p</tt> as
     * {@link #DEFAULT_NUM_PRIMES}.
     */
    public MpRSAKeyGenParameterSpec() {
	k = DEFAULT_NUM_PRIMES;
    }

    /**
     * Construct new MeRSA key generation parameters from the given key size.
     * Choose the public exponent as {@link #DEFAULT_EXPONENT}, and the
     * exponent of the prime <tt>p</tt> as {@link #DEFAULT_NUM_PRIMES}. If
     * the key size is invalid, choose the {@link #DEFAULT_KEY_SIZE}.
     * 
     * @param keySize
     *                the key size (&gt;= 512 bits)
     */
    public MpRSAKeyGenParameterSpec(int keySize) {
	super(keySize);
	k = DEFAULT_NUM_PRIMES;
    }

    /**
     * Construct new MeRSA key generation parameters from the given key size and
     * public exponent. The exponent of the prime <tt>p</tt> is set to the
     * {@link #DEFAULT_NUM_PRIMES}. If the key size is invalid, choose the
     * {@link #DEFAULT_KEY_SIZE}. If the public exponent is invalid, choose the
     * {@link #DEFAULT_EXPONENT}.
     * 
     * @param keySize
     *                the key size (&gt;= 512 bits)
     * @param e
     *                the public exponent (must be odd)
     */
    public MpRSAKeyGenParameterSpec(int keySize, FlexiBigInt e) {
	super(keySize, e);
	k = DEFAULT_NUM_PRIMES;
    }

    /**
     * Construct new RSA key generation parameters from the given key size and
     * public exponent. If the key size is invalid, choose the
     * {@link #DEFAULT_KEY_SIZE}. If the public exponent is invalid, choose the
     * {@link #DEFAULT_EXPONENT}. If the exponent of the prime <tt>p</tt> is
     * invalid, choose the {@link #DEFAULT_NUM_PRIMES}.
     * 
     * @param keySize
     *                the key size (&gt;= 512 bits)
     * @param e
     *                the public exponent (must be odd)
     * @param k
     *                the number of primes (&gt;= 2)
     */
    public MpRSAKeyGenParameterSpec(int keySize, FlexiBigInt e, int k) {
	super(keySize, e);
	if (k < 2) {
	    this.k = DEFAULT_NUM_PRIMES;
	} else {
	    this.k = k;
	}
    }

    /**
     * @return the number of primes
     */
    public int getNumPrimes() {
	return k;
    }

}
