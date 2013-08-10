/*
 * Copyright (c) 1998-2008 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */
package de.flexiprovider.core.mac;

import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.keys.SecretKey;
import de.flexiprovider.api.keys.SecretKeyGenerator;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;

public class HMacKeyGenerator extends SecretKeyGenerator {

    public static class SHA1 extends HMacKeyGenerator {
	public SHA1() {
	    super(64);
	}
    }

    public static class SHA224 extends HMacKeyGenerator {
	public SHA224() {
	    super(64);
	}
    }

    public static class SHA256 extends HMacKeyGenerator {
	public SHA256() {
	    super(64);
	}
    }

    public static class SHA384 extends HMacKeyGenerator {
	public SHA384() {
	    super(128);
	}
    }

    public static class SHA512 extends HMacKeyGenerator {
	public SHA512() {
	    super(128);
	}
    }

    public static class MD4 extends HMacKeyGenerator {
	public MD4() {
	    super(64);
	}
    }

    public static class MD5 extends HMacKeyGenerator {
	public MD5() {
	    super(64);
	}
    }

    public static class RIPEMD128 extends HMacKeyGenerator {
	public RIPEMD128() {
	    super(64);
	}
    }

    public static class RIPEMD160 extends HMacKeyGenerator {
	public RIPEMD160() {
	    super(64);
	}
    }

    public static class RIPEMD256 extends HMacKeyGenerator {
	public RIPEMD256() {
	    super(64);
	}
    }

    public static class RIPEMD320 extends HMacKeyGenerator {
	public RIPEMD320() {
	    super(64);
	}
    }

    public static class Tiger extends HMacKeyGenerator {
	public Tiger() {
	    super(64);
	}
    }

    public static class DHA256 extends HMacKeyGenerator {
	public DHA256() {
	    super(64);
	}
    }

    public static class FORK256 extends HMacKeyGenerator {
	public FORK256() {
	    super(64);
	}
    }

    // the key size in bits
    private int keySize;

    // the source of randomness
    private SecureRandom random;

    // flag indicating whether the key generator has been initialized
    private boolean initialized;

    /**
     * Constructor. Set the key size.
     * 
     * @param keySize
     *                the key size in bits
     */
    protected HMacKeyGenerator(int keySize) {
	this.keySize = keySize;
    }

    /**
     * Initialize the key generator. Since the key size is set by the concrete
     * instantiations and no further parameters are used, the parameters are
     * ignored and only the source of randomness is set.
     * 
     * @param params
     *                the parameters (not used)
     * @param random
     *                the source of randomness
     */
    public void init(AlgorithmParameterSpec params, SecureRandom random) {
	init(random);
    }

    /**
     * Initialize the key generator. Since the key size is set by the concrete
     * instantiations, the key size parameter is ignored and only the source of
     * randomness is set.
     * 
     * @param keySize
     *                the key size (not used)
     * @param random
     *                the source of randomness
     */
    public void init(int keySize, SecureRandom random) {
	init(random);
    }

    /**
     * Initialize the key generator with a source of randomness.
     * 
     * @param random
     *                the source of randomness
     */
    public void init(SecureRandom random) {
	this.random = random != null ? random : Registry.getSecureRandom();
	initialized = true;
    }

    /**
     * Generate an HMac key.
     * 
     * @return the generated {@link HMacKey}
     */
    public SecretKey generateKey() {
	if (!initialized) {
	    init(Registry.getSecureRandom());
	}

	byte[] keyBytes = new byte[keySize >> 3];
	random.nextBytes(keyBytes);

	return new HMacKey(keyBytes);
    }

}
