package de.flexiprovider.core.mersa;

import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.core.rsa.RSAKeyGenParameterSpec;

/**
 * This class specifies parameters used by the {@link MeRSAKeyPairGenerator}.
 * 
 * @author Paul Nguentcheu
 * @author Martin Döring
 */
public class MeRSAKeyGenParameterSpec extends RSAKeyGenParameterSpec {

    /**
     * The default exponent of the prime <tt>p</tt>
     */
    public static final int DEFAULT_EXPONENT_K = 3;

    // the exponent of the prime p
    private int k;

    /**
     * Construct the default MeRSA key generation parameters. Choose the key
     * size as {@link #DEFAULT_KEY_SIZE}, the public exponent as
     * {@link #DEFAULT_EXPONENT}, and the exponent of the prime <tt>p</tt> as
     * {@link #DEFAULT_EXPONENT_K}.
     */
    public MeRSAKeyGenParameterSpec() {
	k = DEFAULT_EXPONENT_K;
    }

    /**
     * Construct new MeRSA key generation parameters from the given key size.
     * Choose the public exponent as {@link #DEFAULT_EXPONENT}, and the
     * exponent of the prime <tt>p</tt> as {@link #DEFAULT_EXPONENT_K}. If
     * the key size is invalid, choose the {@link #DEFAULT_KEY_SIZE}.
     * 
     * @param keySize
     *                the key size (&gt;= 512 bits)
     */
    public MeRSAKeyGenParameterSpec(int keySize) {
	super(keySize);
	k = DEFAULT_EXPONENT_K;
    }

    /**
     * Construct new MeRSA key generation parameters from the given key size and
     * public exponent. The exponent of the prime <tt>p</tt> is set to the
     * {@link #DEFAULT_EXPONENT_K}. If the key size is invalid, choose the
     * {@link #DEFAULT_KEY_SIZE}. If the public exponent is invalid, choose the
     * {@link #DEFAULT_EXPONENT}.
     * 
     * @param keySize
     *                the key size (&gt;= 512 bits)
     * @param e
     *                the public exponent (must be odd)
     */
    public MeRSAKeyGenParameterSpec(int keySize, FlexiBigInt e) {
	super(keySize, e);
	k = DEFAULT_EXPONENT_K;
    }

    /**
     * Construct new RSA key generation parameters from the given key size and
     * public exponent. If the key size is invalid, choose the
     * {@link #DEFAULT_KEY_SIZE}. If the public exponent is invalid, choose the
     * {@link #DEFAULT_EXPONENT}. If the exponent of the prime <tt>p</tt> is
     * invalid, choose the {@link #DEFAULT_EXPONENT_K}.
     * 
     * @param keySize
     *                the key size (&gt;= 512 bits)
     * @param e
     *                the public exponent (must be odd)
     * @param k
     *                the exponent of the prime <tt>p</tt> (&gt;= 1)
     */
    public MeRSAKeyGenParameterSpec(int keySize, FlexiBigInt e, int k) {
	super(keySize, e);
	if (k < 1) {
	    this.k = DEFAULT_EXPONENT_K;
	} else {
	    this.k = k;
	}
    }

    /**
     * @return the exponent of the prime <tt>p</tt>
     */
    public int getExponentK() {
	return k;
    }

}
