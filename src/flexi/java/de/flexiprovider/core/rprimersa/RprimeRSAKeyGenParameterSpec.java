package de.flexiprovider.core.rprimersa;

import de.flexiprovider.api.parameters.AlgorithmParameterSpec;

/**
 * This class specifies parameters used by the {@link RprimeRSAKeyPairGenerator}.
 * 
 * @author Paul Nguentcheu
 * @author Martin Döring
 */
public final class RprimeRSAKeyGenParameterSpec implements
	AlgorithmParameterSpec {

    /**
     * The default bit length of the modulus <tt>n</tt> (1024 bits)
     */
    public static final int DEFAULT_KEY_SIZE = 1024;

    /**
     * The default number of primes
     */
    public static final int DEFAULT_NUM_PRIMES = 3;

    /**
     * The default bit length of the private exponent <tt>d</tt> modulo all
     * primes
     */
    public static final int DEFAULT_PRIVATE_EXPONENT_SIZE = 160;

    // the bit length of the modulus
    private int keySize;

    // the number of primes
    private int k;

    // the bit length of the private exponent d modulo all primes
    private int s;

    /**
     * Construct the default rebalanced multi-prime RSA key generation
     * parameters. The key size is chosen as {@link #DEFAULT_KEY_SIZE}. The
     * number of primes is chosen as {@link #DEFAULT_NUM_PRIMES}. The bit
     * length of the private exponent <tt>d</tt> modulo all primes is chosen
     * as {@link #DEFAULT_PRIVATE_EXPONENT_SIZE}.
     */
    public RprimeRSAKeyGenParameterSpec() {
	this(DEFAULT_KEY_SIZE, DEFAULT_NUM_PRIMES,
		DEFAULT_PRIVATE_EXPONENT_SIZE);
    }

    /**
     * Construct new rebalanced multi-prime RSA key generation parameters from
     * the given key size. The number of primes is chosen as
     * {@link #DEFAULT_NUM_PRIMES}. The bit length of the private exponent
     * <tt>d</tt> modulo all primes is chosen as
     * {@link #DEFAULT_PRIVATE_EXPONENT_SIZE}. If the key size is invalid,
     * choose the {@link #DEFAULT_KEY_SIZE}.
     * 
     * @param keySize
     *                the bit length of the modulus <tt>n</tt> (&gt;= 512)
     */
    public RprimeRSAKeyGenParameterSpec(int keySize) {
	this(keySize, DEFAULT_NUM_PRIMES, DEFAULT_PRIVATE_EXPONENT_SIZE);
    }

    /**
     * Construct new rebalanced multi-prime RSA key generation parameters from
     * the given key size and number of primes. The bit length of the private
     * exponent <tt>d</tt> modulo all primes is chosen as
     * {@link #DEFAULT_PRIVATE_EXPONENT_SIZE}. If the key size is invalid,
     * choose the {@link #DEFAULT_KEY_SIZE}. If the number of primes is
     * invalid, choose the {@link #DEFAULT_NUM_PRIMES}.
     * 
     * @param keySize
     *                the bit length of the modulus <tt>n</tt> (&gt;= 512)
     * @param k
     *                the number of primes (&gt;= 2)
     */
    public RprimeRSAKeyGenParameterSpec(int keySize, int k) {
	this(keySize, k, DEFAULT_PRIVATE_EXPONENT_SIZE);
    }

    /**
     * Construct new rebalanced multi-prime RSA key generation parameters from
     * the given key size, number of primes, and bit length of the private
     * exponent <tt>d</tt> modulo all primes. If the key size is invalid,
     * choose the {@link #DEFAULT_KEY_SIZE}. If the number of primes is
     * invalid, choose the {@link #DEFAULT_NUM_PRIMES}. If the bit length of
     * the private exponent is invalid, choose the
     * {@link #DEFAULT_PRIVATE_EXPONENT_SIZE}.
     * 
     * @param keySize
     *                the bit length of the modulus <tt>n</tt> (&gt;= 512)
     * @param k
     *                the number of primes (&gt;= 2)
     * @param s
     *                the bit length of the private exponent <tt>d</tt> modulo
     *                all primes (&gt;= 2)
     */
    public RprimeRSAKeyGenParameterSpec(int keySize, int k, int s) {
	if (keySize < 512) {
	    this.keySize = DEFAULT_KEY_SIZE;
	} else {
	    this.keySize = keySize;
	}

	if (k < 2) {
	    this.k = DEFAULT_NUM_PRIMES;
	} else {
	    this.k = k;
	}

	if (s < 2) {
	    this.s = DEFAULT_PRIVATE_EXPONENT_SIZE;
	} else {
	    this.s = s;
	}
    }

    /**
     * @return the bit length of the modulus <tt>n</tt>
     */
    public int getKeySize() {
	return keySize;
    }

    /**
     * @return the number of primes
     */
    public int getNumPrimes() {
	return k;
    }

    /**
     * @return the bit length of the private exponent <tt>d</tt> modulo all
     *         primes
     */
    public int getPrivExpSize() {
	return s;
    }

}
