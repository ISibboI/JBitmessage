/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.mac;

import de.flexiprovider.api.Mac;
import de.flexiprovider.api.MessageDigest;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;

/**
 * This class extends the MAC class for providing the functionality of the
 * HMAC(Keyed-Hashing for Message Authentication) algorithm, as specified in <a
 * href="http://rfc.net/rfc2104.html">RFC 2104</a>.
 * <p>
 * Any application dealing with MAC computation uses the "getInstance"-method of
 * the MAC class for creating a MAC object.
 * <p>
 * The FlexiProvider supports HMAC computation based on SHA1, MD5, and RIPEMD160
 * hash algorithms.
 */
public class HMac extends Mac {

    /*
     * Inner classes providing concrete implementations of HMac with a variety
     * of message digests.
     */

    public static class SHA1 extends HMac {

	/**
	 * The OID of HmacSHA1 (defined by RFC 3370).
	 */
	public static final String OID = "1.3.6.1.5.5.8.1.2";

	/**
	 * An alternative OID of HmacSHA1 (defined by PKCS #5 v2.0)
	 */
	public static final String PKCS5_OID = "1.2.840.113549.2.7";

	public SHA1() {
	    super(new de.flexiprovider.core.md.SHA1(), 64);
	}
    }

    public static class SHA224 extends HMac {
	public SHA224() {
	    super(new de.flexiprovider.core.md.SHA224(), 64);
	}
    }

    public static class SHA256 extends HMac {
	public SHA256() {
	    super(new de.flexiprovider.core.md.SHA256(), 64);
	}
    }

    public static class SHA384 extends HMac {
	public SHA384() {
	    super(new de.flexiprovider.core.md.SHA384(), 128);
	}
    }

    public static class SHA512 extends HMac {
	public SHA512() {
	    super(new de.flexiprovider.core.md.SHA512(), 128);
	}
    }

    public static class MD4 extends HMac {
	public MD4() {
	    super(new de.flexiprovider.core.md.MD4(), 64);
	}
    }

    public static class MD5 extends HMac {

	/**
	 * The OID of HmacMD5 (defined by RFC 3370).
	 */
	public static final String OID = "1.3.6.1.5.5.8.1.1";

	public MD5() {
	    super(new de.flexiprovider.core.md.MD5(), 64);
	}
    }

    public static class RIPEMD128 extends HMac {
	public RIPEMD128() {
	    super(new de.flexiprovider.core.md.RIPEMD128(), 64);
	}
    }

    public static class RIPEMD160 extends HMac {

	/**
	 * The OID of HmacRIPEMD160 (defined by RFC 3370).
	 */
	public static final String OID = "1.3.6.1.5.5.8.1.4";

	public RIPEMD160() {
	    super(new de.flexiprovider.core.md.RIPEMD160(), 64);
	}
    }

    public static class RIPEMD256 extends HMac {
	public RIPEMD256() {
	    super(new de.flexiprovider.core.md.RIPEMD256(), 64);
	}
    }

    public static class RIPEMD320 extends HMac {
	public RIPEMD320() {
	    super(new de.flexiprovider.core.md.RIPEMD320(), 64);
	}
    }

    public static class Tiger extends HMac {

	/**
	 * The OID of HmacTiger (defined by RFC 3370).
	 */
	public static final String OID = "1.3.6.1.5.5.8.1.3";

	public Tiger() {
	    super(new de.flexiprovider.core.md.Tiger(), 64);
	}
    }

    public static class DHA256 extends HMac {
	public DHA256() {
	    super(new de.flexiprovider.core.md.DHA256(), 64);
	}
    }

    public static class FORK256 extends HMac {
	public FORK256() {
	    super(new de.flexiprovider.core.md.FORK256(), 64);
	}
    }

    private static final byte IPAD_BYTE = 0x36;

    private static final byte OPAD_BYTE = 0x5c;

    private int L, B;

    private byte[] macKey;

    private byte[] ipadKey;

    private byte[] opadKey;

    private MessageDigest md;

    /**
     * Creates a new HMac for the specified hash algorithm.
     * 
     * This constructor is called by every subclass for specifying the
     * particular hash algorithm to be used for HMac computation.
     * 
     * @param md
     *                the hash algorithm to use.
     * @param blockSize
     *                TODO
     */
    HMac(MessageDigest md, int blockSize) {
	this.md = md;
	L = md.getDigestLength();
	B = blockSize;
    }

    /**
     * @return the length of the calculated MAC value in bytes
     */
    public int getMacLength() {
	return L;
    }

    /**
     * Initialize this MAC object with the given key and algorithm parameters
     * (not used).
     * 
     * @param key
     *                the MAC key
     * @param params
     *                the algorithm parameters (not used)
     * @throws InvalidKeyException
     *                 if the key is not an instance of {@link HMacKey}.
     */
    public void init(SecretKey key, AlgorithmParameterSpec params)
	    throws InvalidKeyException {

	// TODO: the PKCS#12 routines of the FhG codec call init() with a
	// PBEKey to calculate an iterated MAC with salt.
	if (!(key instanceof HMacKey)) {
	    throw new InvalidKeyException("unsupported type");
	}

	byte[] keyBytes = ((HMacKey) key).getEncoded();
	macKey = new byte[B];
	// If the key is too short, it has to be filled up with zeroes. If it is
	// too long, it has to be hashed.
	if (keyBytes.length <= B) {
	    System.arraycopy(keyBytes, 0, macKey, 0, keyBytes.length);
	} else {
	    md.update(keyBytes);
	    byte[] keyDigest = md.digest();
	    System.arraycopy(keyDigest, 0, macKey, 0, keyDigest.length);
	}

	// initialize ipadKey and opadKey
	ipadKey = new byte[B];
	opadKey = new byte[B];
	for (int i = B - 1; i >= 0; i--) {
	    ipadKey[i] = (byte) (macKey[i] ^ IPAD_BYTE);
	    opadKey[i] = (byte) (macKey[i] ^ OPAD_BYTE);
	}

	// feed the message digest with (macKey XOR ipadKey)
	md.update(ipadKey);
    }

    /**
     * Processes the given number of bytes, supplied in a byte array starting at
     * the given position.
     * 
     * @param input
     *                the byte array containing the input
     * @param inOff
     *                the offset where the input starts
     * @param inLen
     *                the length of the input
     */
    public void update(byte[] input, int inOff, int inLen) {
	md.update(input, inOff, inLen);
    }

    /**
     * Process the given byte.
     * 
     * @param input
     *                the byte to be processed
     */
    public void update(byte input) {
	md.update(input);
    }

    /**
     * Return the computed MAC value. After the MAC has been computed, the MAC
     * object is reset and has to be initialized again for further MAC
     * computations.
     * 
     * @return the computed MAC value
     */
    public byte[] doFinal() {
	byte[] hash1 = md.digest();
	md.update(opadKey);
	md.update(hash1);
	return md.digest();
    }

    /**
     * Resets this MAC object so that it may be used for further MAC
     * comptations.
     */
    public void reset() {
	md.reset();
    }

}
