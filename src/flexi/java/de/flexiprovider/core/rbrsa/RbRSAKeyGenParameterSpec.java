package de.flexiprovider.core.rbrsa;

import de.flexiprovider.api.parameters.AlgorithmParameterSpec;

/**
 * This class specifies parameters used by the {@link RbRSAKeyPairGenerator}.
 * 
 * @author Paul Nguentcheu
 * @author Martin Döring
 */
public class RbRSAKeyGenParameterSpec implements AlgorithmParameterSpec {

    /**
     * The default bit length of the modulus <tt>n</tt> (1024 bits)
     */
    public static final int DEFAULT_KEY_SIZE = 1024;

    /**
     * The default bit length of the private exponent <tt>d</tt> modulo
     * <tt>p</tt> and modulo <tt>q</tt> (160 bits)
     */
    public static final int DEFAULT_PRIVATE_EXPONENT_SIZE = 160;

    // the bit length of the modulus n
    private int keySize;

    // the bit length of the private exponent d modulo p and modulo q
    private int s;

    /**
     * Construct the default rebalanced RSA key generation parameters. The key
     * size is chosen as {@link #DEFAULT_KEY_SIZE}. The bit length of the prime
     * <tt>p</tt> modulo <tt>p</tt> and modulo <tt>q</tt> is chosen as
     * {@link #DEFAULT_PRIVATE_EXPONENT_SIZE}.
     */
    public RbRSAKeyGenParameterSpec() {
	this(DEFAULT_KEY_SIZE, DEFAULT_PRIVATE_EXPONENT_SIZE);
    }

    /**
     * Construct new rebalanced RSA key generation parameters from the given key
     * size. The bit length of the prime <tt>p</tt> modulo <tt>p</tt> and
     * modulo <tt>q</tt> is chosen as {@link #DEFAULT_PRIVATE_EXPONENT_SIZE}.
     * If the key size is invalid, choose the {@link #DEFAULT_KEY_SIZE}.
     * 
     * @param keySize
     *                the bit length of the modulus <tt>n</tt> (&gt;= 512)
     */
    public RbRSAKeyGenParameterSpec(int keySize) {
	this(keySize, DEFAULT_PRIVATE_EXPONENT_SIZE);
    }

    /**
     * Construct new rebalanced RSA key generation parameters from the given key
     * size and bit length of the prime <tt>p</tt> modulo <tt>p</tt> and
     * modulo <tt>q</tt>. If the key size is invalid, choose the
     * {@link #DEFAULT_KEY_SIZE}. If the bit length of the prime <tt>p</tt>
     * is invalid, choose the {@link #DEFAULT_PRIVATE_EXPONENT_SIZE}.
     * 
     * @param keySize
     *                the bit length of the modulus <tt>n</tt> (&gt;= 512)
     * @param s
     *                the bit length of the prime <tt>p</tt> modulo <tt>p</tt>
     *                and modulo <tt>q</tt> (&gt;= 2)
     */
    public RbRSAKeyGenParameterSpec(int keySize, int s) {
	if (keySize < 512) {
	    this.keySize = DEFAULT_KEY_SIZE;
	} else {
	    this.keySize = keySize;
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
     * @return the bit length of the private exponent <tt>d</tt> modulo
     *         <tt>p</tt> and modulo <tt>q</tt>
     */
    public int getPrivExpSize() {
	return s;
    }

}
