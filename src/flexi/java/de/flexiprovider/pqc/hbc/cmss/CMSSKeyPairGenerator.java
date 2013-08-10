package de.flexiprovider.pqc.hbc.cmss;

import de.flexiprovider.api.MessageDigest;
import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.keys.KeyPair;
import de.flexiprovider.api.keys.KeyPairGenerator;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.math.IntegerFunctions;
import de.flexiprovider.common.util.ByteUtils;
import de.flexiprovider.core.md.SHA1;
import de.flexiprovider.core.md.SHA256;
import de.flexiprovider.core.md.SHA384;
import de.flexiprovider.core.md.SHA512;
import de.flexiprovider.core.md.swifftx.SWIFFTX224;
import de.flexiprovider.core.md.swifftx.SWIFFTX256;
import de.flexiprovider.core.md.swifftx.SWIFFTX384;
import de.flexiprovider.core.md.swifftx.SWIFFTX512;
import de.flexiprovider.pqc.hbc.FIPS_186_2_PRNG;
import de.flexiprovider.pqc.hbc.PRNG;
import de.flexiprovider.pqc.hbc.cmss.CMSSSignature;
import de.flexiprovider.pqc.hbc.ots.BiBaOTS;
import de.flexiprovider.pqc.hbc.ots.OTS;
import de.flexiprovider.pqc.hbc.ots.WinternitzOTS;
import de.flexiprovider.pqc.hbc.ots.WinternitzPRFOTS;
import de.flexiprovider.pqc.hbc.ots.LMOTS;

/**
 * This class implements key pair generation of the Coronado-Merkle signature
 * scheme (CMSS). The class extends the KeyPairGeneratorSpi class. It is able to
 * use the SPR hash functions as described in E. Dahmen et al., "Digital
 * Signatures Out of Second-Preimage Resistant Hash Functions".
 * <p>
 * The CMSSKeyPairGenerator can be used as follows:
 * <p>
 * 1. get instance of CMSS key pair generator:<br/> <tt>KeyPairGenerator kpg =
 * KeyPairGenerator.getInstance("SHA1andWinternitzOTS_1",
 * "FlexiPQC");</tt><br/>
 * 2. initialize the KPG with the desired height of the trees:<br/>
 * <tt>kpg.initialize(heightOfTrees);</tt><br/> 3. create CMSS key pair:<br/>
 * <tt>KeyPair keyPair = kpg.generateKeyPair();</tt><br/> 4. get the encoded
 * private and public keys from the key pair:<br/>
 * <tt>encodedPublicKey = keyPair.getPublic().getEncoded();<br/>
 * encodedPrivateKey = keyPair.getPrivate().getEncoded();</tt>
 * 
 * @author Elena Klintsevich
 * @see CMSSSignature
 */
public class CMSSKeyPairGenerator extends KeyPairGenerator {

    // the OID string of the algorithm
    private String oidString;

    // the message digest used to build the authentication trees and for the OTS
    private MessageDigest md;

    // the output length of the message digest
    private int mdLength;

    // the one-time signature scheme
    private OTS ots;

    // the RNG used for key pair generation
    private PRNG rng;

    // the PRNG used for OTS key pair generation
    private SecureRandom sr;

    // the height of the authentication trees
    private int heightOfTrees;

    // an array of three seeds for the PRNG (main tree, current subtree, and
    // next subtree)
    private byte[][] seeds;

    // flag indicating if the key pair generator has been initialized
    private boolean initialized = false;

    private boolean useSpr;

    // //////////////////////////////////////////////////////////////////////////////

    /*
     * Inner classes providing concrete implementations of the CMSS2 key pair
     * generator with a variety of message digests and one-time signature
     * schemes.
     */

    /**
     * CMSSKeyPairGenerator with SHA1 message digest, Winternitz OTS with
     * parameter w=1, and SHA1PRNG
     */
    public static class SHA1andWinternitzOTS_1 extends CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.1";

	/**
	 * Constructor.
	 */
	public SHA1andWinternitzOTS_1() {
	    super(OID, new SHA1(), new WinternitzOTS(1), false);
	}
    }

    /**
     * CMSSKeyPairGenerator with SHA1 message digest, Winternitz OTS with
     * parameter w=2, and SHA1PRNG
     */
    public static class SHA1andWinternitzOTS_2 extends CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.2";

	/**
	 * Constructor.
	 */
	public SHA1andWinternitzOTS_2() {
	    super(OID, new SHA1(), new WinternitzOTS(2), false);
	}
    }

    /**
     * CMSSKeyPairGenerator with SHA1 message digest, Winternitz OTS with
     * parameter w=3, and SHA1PRNG
     */
    public static class SHA1andWinternitzOTS_3 extends CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.3";

	/**
	 * Constructor.
	 */
	public SHA1andWinternitzOTS_3() {
	    super(OID, new SHA1(), new WinternitzOTS(3), false);
	}
    }

    /**
     * CMSSKeyPairGenerator with SHA1 message digest, Winternitz OTS with
     * parameter w=4, and SHA1PRNG
     */
    public static class SHA1andWinternitzOTS_4 extends CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.4";

	/**
	 * Constructor.
	 */
	public SHA1andWinternitzOTS_4() {
	    super(OID, new SHA1(), new WinternitzOTS(4), false);
	}
    }

    /**
     * CMSSKeyPairGenerator with SHA256 message digest, Winternitz OTS with
     * parameter w=1, and SHA1PRNG
     */
    public static class SHA256andWinternitzOTS_1 extends CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.5";

	/**
	 * Constructor.
	 */
	public SHA256andWinternitzOTS_1() {
	    super(OID, new SHA256(), new WinternitzOTS(1), false);
	}
    }

    /**
     * CMSSKeyPairGenerator with SHA256 message digest, Winternitz OTS with
     * parameter w=2, and SHA1PRNG
     */
    public static class SHA256andWinternitzOTS_2 extends CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.6";

	/**
	 * Constructor.
	 */
	public SHA256andWinternitzOTS_2() {
	    super(OID, new SHA256(), new WinternitzOTS(2), false);
	}
    }

    /**
     * CMSSKeyPairGenerator with SHA256 message digest, Winternitz OTS with
     * parameter w=3, and SHA1PRNG
     */
    public static class SHA256andWinternitzOTS_3 extends CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.7";

	/**
	 * Constructor.
	 */
	public SHA256andWinternitzOTS_3() {
	    super(OID, new SHA256(), new WinternitzOTS(3), false);
	}
    }

    /**
     * CMSSKeyPairGenerator with SHA256 message digest, Winternitz OTS with
     * parameter w=4, and SHA1PRNG
     */
    public static class SHA256andWinternitzOTS_4 extends CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.8";

	/**
	 * Constructor.
	 */
	public SHA256andWinternitzOTS_4() {
	    super(OID, new SHA256(), new WinternitzOTS(4), false);
	}
    }

    /**
     * CMSSKeyPairGenerator with SHA384 message digest, Winternitz OTS with
     * parameter w=1, and SHA1PRNG
     */
    public static class SHA384andWinternitzOTS_1 extends CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.9";

	/**
	 * Constructor.
	 */
	public SHA384andWinternitzOTS_1() {
	    super(OID, new SHA384(), new WinternitzOTS(1), false);
	}
    }

    /**
     * CMSSKeyPairGenerator with SHA384 message digest, Winternitz OTS with
     * parameter w=2, and SHA1PRNG
     */
    public static class SHA384andWinternitzOTS_2 extends CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.10";

	/**
	 * Constructor.
	 */
	public SHA384andWinternitzOTS_2() {
	    super(OID, new SHA384(), new WinternitzOTS(2), false);
	}
    }

    /**
     * CMSSKeyPairGenerator with SHA384 message digest, Winternitz OTS with
     * parameter w=3, and SHA1PRNG
     */
    public static class SHA384andWinternitzOTS_3 extends CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.11";

	/**
	 * Constructor.
	 */
	public SHA384andWinternitzOTS_3() {
	    super(OID, new SHA384(), new WinternitzOTS(3), false);
	}
    }

    /**
     * CMSSKeyPairGenerator with SHA384 message digest, Winternitz OTS with
     * parameter w=4, and SHA1PRNG
     */
    public static class SHA384andWinternitzOTS_4 extends CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.12";

	/**
	 * Constructor.
	 */
	public SHA384andWinternitzOTS_4() {
	    super(OID, new SHA384(), new WinternitzOTS(4), false);
	}
    }

    /**
     * CMSSKeyPairGenerator with SHA512 message digest, Winternitz OTS with
     * parameter w=1, and SHA1PRNG
     */
    public static class SHA512andWinternitzOTS_1 extends CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.13";

	/**
	 * Constructor.
	 */
	public SHA512andWinternitzOTS_1() {
	    super(OID, new SHA512(), new WinternitzOTS(1), false);
	}
    }

    /**
     * CMSSKeyPairGenerator with SHA512 message digest, Winternitz OTS with
     * parameter w=2, and SHA1PRNG
     */
    public static class SHA512andWinternitzOTS_2 extends CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.14";

	/**
	 * Constructor.
	 */
	public SHA512andWinternitzOTS_2() {
	    super(OID, new SHA512(), new WinternitzOTS(2), false);
	}
    }

    /**
     * CMSSKeyPairGenerator with SHA512 message digest, Winternitz OTS with
     * parameter w=3, and SHA1PRNG
     */
    public static class SHA512andWinternitzOTS_3 extends CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.15";

	/**
	 * Constructor.
	 */
	public SHA512andWinternitzOTS_3() {
	    super(OID, new SHA512(), new WinternitzOTS(3), false);
	}
    }

    /**
     * CMSSKeyPairGenerator with SHA512 message digest, Winternitz OTS with
     * parameter w=4, and SHA1PRNG
     */
    public static class SHA512andWinternitzOTS_4 extends CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.16";

	/**
	 * Constructor.
	 */
	public SHA512andWinternitzOTS_4() {
	    super(OID, new SHA512(), new WinternitzOTS(4), false);
	}
    }

    /**
     * CMSSKeyPairGenerator with SWIFFTX224 message digest, Winternitz OTS with
     * parameter w=1, and SWIFFTX224PRNG
     */
    public static class SWIFFTX224andWinternitzOTS_1 extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.101";

	/**
	 * Constructor.
	 */
	public SWIFFTX224andWinternitzOTS_1() {
	    super(OID, new SWIFFTX224(), new WinternitzOTS(1), false);
	}
    }

    /**
     * CMSSKeyPairGenerator with SWIFFTX224 message digest, Winternitz OTS with
     * parameter w=2, and SWIFFTX224PRNG
     */
    public static class SWIFFTX224andWinternitzOTS_2 extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.102";

	/**
	 * Constructor.
	 */
	public SWIFFTX224andWinternitzOTS_2() {
	    super(OID, new SWIFFTX224(), new WinternitzOTS(2), false);
	}
    }

    /**
     * CMSSKeyPairGenerator with SWIFFTX224 message digest, Winternitz OTS with
     * parameter w=3, and SWIFFTX224PRNG
     */
    public static class SWIFFTX224andWinternitzOTS_3 extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.103";

	/**
	 * Constructor.
	 */
	public SWIFFTX224andWinternitzOTS_3() {
	    super(OID, new SWIFFTX224(), new WinternitzOTS(3), false);
	}
    }

    /**
     * CMSSKeyPairGenerator with SWIFFTX224 message digest, Winternitz OTS with
     * parameter w=4, and SWIFFTX224PRNG
     */
    public static class SWIFFTX224andWinternitzOTS_4 extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.104";

	/**
	 * Constructor.
	 */
	public SWIFFTX224andWinternitzOTS_4() {
	    super(OID, new SWIFFTX224(), new WinternitzOTS(4), false);
	}
    }

    /**
     * CMSSKeyPairGenerator with SWIFFTX256 message digest, Winternitz OTS with
     * parameter w=1, and SWIFFTX256PRNG
     */
    public static class SWIFFTX256andWinternitzOTS_1 extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.105";

	/**
	 * Constructor.
	 */
	public SWIFFTX256andWinternitzOTS_1() {
	    super(OID, new SWIFFTX256(), new WinternitzOTS(1), false);
	}
    }

    /**
     * CMSSKeyPairGenerator with SWIFFTX256 message digest, Winternitz OTS with
     * parameter w=2, and SWIFFTX256PRNG
     */
    public static class SWIFFTX256andWinternitzOTS_2 extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.106";

	/**
	 * Constructor.
	 */
	public SWIFFTX256andWinternitzOTS_2() {
	    super(OID, new SWIFFTX256(), new WinternitzOTS(2), false);
	}
    }

    /**
     * CMSSKeyPairGenerator with SWIFFTX256 message digest, Winternitz OTS with
     * parameter w=3, and SWIFFTX256PRNG
     */
    public static class SWIFFTX256andWinternitzOTS_3 extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.107";

	/**
	 * Constructor.
	 */
	public SWIFFTX256andWinternitzOTS_3() {
	    super(OID, new SWIFFTX256(), new WinternitzOTS(3), false);
	}
    }

    /**
     * CMSSKeyPairGenerator with SWIFFTX256 message digest, Winternitz OTS with
     * parameter w=4, and SWIFFTX256PRNG
     */
    public static class SWIFFTX256andWinternitzOTS_4 extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.108";

	/**
	 * Constructor.
	 */
	public SWIFFTX256andWinternitzOTS_4() {
	    super(OID, new SWIFFTX256(), new WinternitzOTS(4), false);
	}
    }

    /**
     * CMSSKeyPairGenerator with SWIFFTX384 message digest, Winternitz OTS with
     * parameter w=1, and SWIFFTX384PRNG
     */
    public static class SWIFFTX384andWinternitzOTS_1 extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.109";

	/**
	 * Constructor.
	 */
	public SWIFFTX384andWinternitzOTS_1() {
	    super(OID, new SWIFFTX384(), new WinternitzOTS(1), false);
	}
    }

    /**
     * CMSSKeyPairGenerator with SWIFFTX384 message digest, Winternitz OTS with
     * parameter w=2, and SWIFFTX384PRNG
     */
    public static class SWIFFTX384andWinternitzOTS_2 extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.110";

	/**
	 * Constructor.
	 */
	public SWIFFTX384andWinternitzOTS_2() {
	    super(OID, new SWIFFTX384(), new WinternitzOTS(2), false);
	}
    }

    /**
     * CMSSKeyPairGenerator with SWIFFTX384 message digest, Winternitz OTS with
     * parameter w=3, and SWIFFTX384PRNG
     */
    public static class SWIFFTX384andWinternitzOTS_3 extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.111";

	/**
	 * Constructor.
	 */
	public SWIFFTX384andWinternitzOTS_3() {
	    super(OID, new SWIFFTX384(), new WinternitzOTS(3), false);
	}
    }

    /**
     * CMSSKeyPairGenerator with SWIFFTX384 message digest, Winternitz OTS with
     * parameter w=4, and SWIFFTX384PRNG
     */
    public static class SWIFFTX384andWinternitzOTS_4 extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.112";

	/**
	 * Constructor.
	 */
	public SWIFFTX384andWinternitzOTS_4() {
	    super(OID, new SWIFFTX384(), new WinternitzOTS(4), false);
	}
    }

    /**
     * CMSSKeyPairGenerator with SWIFFTX512 message digest, Winternitz OTS with
     * parameter w=1, and SWIFFTX512PRNG
     */
    public static class SWIFFTX512andWinternitzOTS_1 extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.113";

	/**
	 * Constructor.
	 */
	public SWIFFTX512andWinternitzOTS_1() {
	    super(OID, new SWIFFTX512(), new WinternitzOTS(1), false);
	}
    }

    /**
     * CMSSKeyPairGenerator with SWIFFTX512 message digest, Winternitz OTS with
     * parameter w=2, and SWIFFTX512PRNG
     */
    public static class SWIFFTX512andWinternitzOTS_2 extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.114";

	/**
	 * Constructor.
	 */
	public SWIFFTX512andWinternitzOTS_2() {
	    super(OID, new SWIFFTX512(), new WinternitzOTS(2), false);
	}
    }

    /**
     * CMSSKeyPairGenerator with SWIFFTX512 message digest, Winternitz OTS with
     * parameter w=3, and SWIFFTX512PRNG
     */
    public static class SWIFFTX512andWinternitzOTS_3 extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.115";

	/**
	 * Constructor.
	 */
	public SWIFFTX512andWinternitzOTS_3() {
	    super(OID, new SWIFFTX512(), new WinternitzOTS(3), false);
	}
    }

    /**
     * CMSSKeyPairGenerator with SWIFFTX512 message digest, Winternitz OTS with
     * parameter w=4, and SWIFFTX512PRNG
     */
    public static class SWIFFTX512andWinternitzOTS_4 extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.116";

	/**
	 * Constructor.
	 */
	public SWIFFTX512andWinternitzOTS_4() {
	    super(OID, new SWIFFTX512(), new WinternitzOTS(4), false);
	}
    }

    /**
     * CMSSKeyPairGenerator with SHA1 message digest, BiBa OTS and SHA1PRNG
     */
    public static class SHA1andBiBaOTS extends CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.201";

	/**
	 * Constructor.
	 */
	public SHA1andBiBaOTS() {
	    super(OID, new SHA1(), new BiBaOTS(), false);
	}
    }

    /**
     * CMSSKeyPairGenerator with SHA1 message digest, BiBa OTS (security level
     * 50) and SHA1PRNG
     */
    public static class SHA1andBiBaOTS50 extends CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.203";

	/**
	 * Constructor.
	 */
	public SHA1andBiBaOTS50() {
	    super(OID, new SHA1(), new BiBaOTS(new Integer(6),
		    new Integer(994), null, null), false);
	}
    }

    /**
     * CMSSKeyPairGenerator with SHA1 message digest, BiBa OTS (security level
     * 80) and SHA1PRNG
     */
    public static class SHA1andBiBaOTS80 extends CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.205";

	/**
	 * Constructor.
	 */
	public SHA1andBiBaOTS80() {
	    super(OID, new SHA1(), new BiBaOTS(new Integer(11),
		    new Integer(260), null, null), false);
	}
    }

    // SPR classes

    /**
     * CMSSKeyPairGenerator with SHA1 message digest, BiBa OTS and SHA1PRNG
     * with SPR
     */
    public static class SHA1andBiBaOTSwithSPR extends CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.202";

	/**
	 * Constructor.
	 */
	public SHA1andBiBaOTSwithSPR() {
	    super(OID, new SHA1(), new BiBaOTS(), true);
	}
    }

    /**
     * CMSSKeyPairGenerator with SHA1 message digest, BiBa OTS (security level
     * 50) and SHA1PRNG with SPR
     */
    public static class SHA1andBiBaOTS50withSPR extends CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.204";

	/**
	 * Constructor.
	 */
	public SHA1andBiBaOTS50withSPR() {
	    super(OID, new SHA1(), new BiBaOTS(new Integer(6),
		    new Integer(994), null, null), true);
	}
    }

    /**
     * CMSSKeyPairGenerator with SHA1 message digest, BiBa OTS (security level
     * 80) and SHA1PRNG with SPR
     */
    public static class SHA1andBiBaOTS80withSPR extends CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.206";

	/**
	 * Constructor.
	 */
	public SHA1andBiBaOTS80withSPR() {
	    super(OID, new SHA1(), new BiBaOTS(new Integer(11),
		    new Integer(260), null, null), true);
	}
    }

    /**
     * CMSSKeyPairGenerator with SHA1 message digest, Winternitz OTS with
     * parameter w=1, SHA1PRNG and SPR
     */
    public static class SHA1andWinternitzOTS_1withSPR extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.301";

	/**
	 * Constructor.
	 */
	public SHA1andWinternitzOTS_1withSPR() {
	    super(OID, new SHA1(), new WinternitzOTS(1), true);
	}
    }

    /**
     * CMSSKeyPairGenerator with SHA1 message digest, Winternitz OTS with
     * parameter w=2, SHA1PRNG and SPR
     */
    public static class SHA1andWinternitzOTS_2withSPR extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.302";

	/**
	 * Constructor.
	 */
	public SHA1andWinternitzOTS_2withSPR() {
	    super(OID, new SHA1(), new WinternitzOTS(2), true);
	}
    }

    /**
     * CMSSKeyPairGenerator with SHA1 message digest, Winternitz OTS with
     * parameter w=3, SHA1PRNG and SPR
     */
    public static class SHA1andWinternitzOTS_3withSPR extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.303";

	/**
	 * Constructor.
	 */
	public SHA1andWinternitzOTS_3withSPR() {
	    super(OID, new SHA1(), new WinternitzOTS(3), true);
	}
    }

    /**
     * CMSSKeyPairGenerator with SHA1 message digest, Winternitz OTS with
     * parameter w=4, SHA1PRNG and SPR
     */
    public static class SHA1andWinternitzOTS_4withSPR extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.304";

	/**
	 * Constructor.
	 */
	public SHA1andWinternitzOTS_4withSPR() {
	    super(OID, new SHA1(), new WinternitzOTS(4), true);
	}
    }

    /**
     * CMSSKeyPairGenerator with SHA256 message digest, Winternitz OTS with
     * parameter w=1, and SHA1PRNG
     */
    public static class SHA256andWinternitzOTS_1withSPR extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.305";

	/**
	 * Constructor.
	 */
	public SHA256andWinternitzOTS_1withSPR() {
	    super(OID, new SHA256(), new WinternitzOTS(1), true);
	}
    }

    /**
     * CMSSKeyPairGenerator with SHA256 message digest, Winternitz OTS with
     * parameter w=2, and SHA1PRNG
     */
    public static class SHA256andWinternitzOTS_2withSPR extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.306";

	/**
	 * Constructor.
	 */
	public SHA256andWinternitzOTS_2withSPR() {
	    super(OID, new SHA256(), new WinternitzOTS(2), true);
	}
    }

    /**
     * CMSSKeyPairGenerator with SHA256 message digest, Winternitz OTS with
     * parameter w=3, and SHA1PRNG
     */
    public static class SHA256andWinternitzOTS_3withSPR extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.307";

	/**
	 * Constructor.
	 */
	public SHA256andWinternitzOTS_3withSPR() {
	    super(OID, new SHA256(), new WinternitzOTS(3), true);
	}
    }

    /**
     * CMSSKeyPairGenerator with SHA256 message digest, Winternitz OTS with
     * parameter w=4, SHA1PRNG and SPR
     */
    public static class SHA256andWinternitzOTS_4withSPR extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.308";

	/**
	 * Constructor.
	 */
	public SHA256andWinternitzOTS_4withSPR() {
	    super(OID, new SHA256(), new WinternitzOTS(4), true);
	}
    }

    /**
     * CMSSKeyPairGenerator with SHA384 message digest, Winternitz OTS with
     * parameter w=1, SHA1PRNG and SPR
     */
    public static class SHA384andWinternitzOTS_1withSPR extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.309";

	/**
	 * Constructor.
	 */
	public SHA384andWinternitzOTS_1withSPR() {
	    super(OID, new SHA384(), new WinternitzOTS(1), true);
	}
    }

    /**
     * CMSSKeyPairGenerator with SHA384 message digest, Winternitz OTS with
     * parameter w=2, SHA1PRNG and SPR
     */
    public static class SHA384andWinternitzOTS_2withSPR extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.310";

	/**
	 * Constructor.
	 */
	public SHA384andWinternitzOTS_2withSPR() {
	    super(OID, new SHA384(), new WinternitzOTS(2), true);
	}
    }

    /**
     * CMSSKeyPairGenerator with SHA384 message digest, Winternitz OTS with
     * parameter w=3, SHA1PRNG and SPR
     */
    public static class SHA384andWinternitzOTS_3withSPR extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.311";

	/**
	 * Constructor.
	 */
	public SHA384andWinternitzOTS_3withSPR() {
	    super(OID, new SHA384(), new WinternitzOTS(3), true);
	}
    }

    /**
     * CMSSKeyPairGenerator with SHA384 message digest, Winternitz OTS with
     * parameter w=4, SHA1PRNG and SPR
     */
    public static class SHA384andWinternitzOTS_4withSPR extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.312";

	/**
	 * Constructor.
	 */
	public SHA384andWinternitzOTS_4withSPR() {
	    super(OID, new SHA384(), new WinternitzOTS(4), true);
	}
    }

    /**
     * CMSSKeyPairGenerator with SHA512 message digest, Winternitz OTS with
     * parameter w=1, SHA1PRNG and SPR
     */
    public static class SHA512andWinternitzOTS_1withSPR extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.313";

	/**
	 * Constructor.
	 */
	public SHA512andWinternitzOTS_1withSPR() {
	    super(OID, new SHA512(), new WinternitzOTS(1), true);
	}
    }

    /**
     * CMSSKeyPairGenerator with SHA512 message digest, Winternitz OTS with
     * parameter w=2, SHA1PRNG and SPR
     */
    public static class SHA512andWinternitzOTS_2withSPR extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.314";

	/**
	 * Constructor.
	 */
	public SHA512andWinternitzOTS_2withSPR() {
	    super(OID, new SHA512(), new WinternitzOTS(2), true);
	}
    }

    /**
     * CMSSKeyPairGenerator with SHA512 message digest, Winternitz OTS with
     * parameter w=3, SHA1PRNG and SPR
     */
    public static class SHA512andWinternitzOTS_3withSPR extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.315";

	/**
	 * Constructor.
	 */
	public SHA512andWinternitzOTS_3withSPR() {
	    super(OID, new SHA512(), new WinternitzOTS(3), true);
	}
    }

    /**
     * CMSSKeyPairGenerator with SHA512 message digest, Winternitz OTS with
     * parameter w=4, SHA1PRNG and SPR
     */
    public static class SHA512andWinternitzOTS_4withSPR extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.316";

	/**
	 * Constructor.
	 */
	public SHA512andWinternitzOTS_4withSPR() {
	    super(OID, new SHA512(), new WinternitzOTS(4), true);
	}
    }

    /**
     * CMSSKeyPairGenerator with SWIFFTX224 message digest, Winternitz OTS with
     * parameter w=1, SWIFFTX224PRNG and SPR
     */
    public static class SWIFFTX224andWinternitzOTS_1withSPR extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.401";

	/**
	 * Constructor.
	 */
	public SWIFFTX224andWinternitzOTS_1withSPR() {
	    super(OID, new SWIFFTX224(), new WinternitzOTS(1), true);
	}
    }

    /**
     * CMSSKeyPairGenerator with SWIFFTX224 message digest, Winternitz OTS with
     * parameter w=2, SWIFFTX224PRNG and SPR
     */
    public static class SWIFFTX224andWinternitzOTS_2withSPR extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.402";

	/**
	 * Constructor.
	 */
	public SWIFFTX224andWinternitzOTS_2withSPR() {
	    super(OID, new SWIFFTX224(), new WinternitzOTS(2), true);
	}
    }

    /**
     * CMSSKeyPairGenerator with SWIFFTX224 message digest, Winternitz OTS with
     * parameter w=3, SWIFFTX224PRNG and SPR
     */
    public static class SWIFFTX224andWinternitzOTS_3withSPR extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.403";

	/**
	 * Constructor.
	 */
	public SWIFFTX224andWinternitzOTS_3withSPR() {
	    super(OID, new SWIFFTX224(), new WinternitzOTS(3), true);
	}
    }

    /**
     * CMSSKeyPairGenerator with SWIFFTX224 message digest, Winternitz OTS with
     * parameter w=4, SWIFFTX224PRNG and SPR
     */
    public static class SWIFFTX224andWinternitzOTS_4withSPR extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.404";

	/**
	 * Constructor.
	 */
	public SWIFFTX224andWinternitzOTS_4withSPR() {
	    super(OID, new SWIFFTX224(), new WinternitzOTS(4), true);
	}
    }

    /**
     * CMSSKeyPairGenerator with SWIFFTX256 message digest, Winternitz OTS with
     * parameter w=1, SWIFFTX224PRNG and SPR
     */
    public static class SWIFFTX256andWinternitzOTS_1withSPR extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.405";

	/**
	 * Constructor.
	 */
	public SWIFFTX256andWinternitzOTS_1withSPR() {
	    super(OID, new SWIFFTX256(), new WinternitzOTS(1), true);
	}
    }

    /**
     * CMSSKeyPairGenerator with SWIFFTX256 message digest, Winternitz OTS with
     * parameter w=2, SWIFFTX224PRNG and SPR
     */
    public static class SWIFFTX256andWinternitzOTS_2withSPR extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.406";

	/**
	 * Constructor.
	 */
	public SWIFFTX256andWinternitzOTS_2withSPR() {
	    super(OID, new SWIFFTX256(), new WinternitzOTS(2), true);
	}
    }

    /**
     * CMSSKeyPairGenerator with SWIFFTX256 message digest, Winternitz OTS with
     * parameter w=3, SWIFFTX224PRNG and SPR
     */
    public static class SWIFFTX256andWinternitzOTS_3withSPR extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.407";

	/**
	 * Constructor.
	 */
	public SWIFFTX256andWinternitzOTS_3withSPR() {
	    super(OID, new SWIFFTX256(), new WinternitzOTS(3), true);
	}
    }

    /**
     * CMSSKeyPairGenerator with SWIFFTX256 message digest, Winternitz OTS with
     * parameter w=4, SWIFFTX224PRNG and SPR
     */
    public static class SWIFFTX256andWinternitzOTS_4withSPR extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.408";

	/**
	 * Constructor.
	 */
	public SWIFFTX256andWinternitzOTS_4withSPR() {
	    super(OID, new SWIFFTX256(), new WinternitzOTS(4), true);
	}
    }

    /**
     * CMSSKeyPairGenerator with SWIFFTX384 message digest, Winternitz OTS with
     * parameter w=1, SWIFFTX224PRNG and SPR
     */
    public static class SWIFFTX384andWinternitzOTS_1withSPR extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.409";

	/**
	 * Constructor.
	 */
	public SWIFFTX384andWinternitzOTS_1withSPR() {
	    super(OID, new SWIFFTX384(), new WinternitzOTS(1), true);
	}
    }

    /**
     * CMSSKeyPairGenerator with SWIFFTX384 message digest, Winternitz OTS with
     * parameter w=2, SWIFFTX224PRNG and SPR
     */
    public static class SWIFFTX384andWinternitzOTS_2withSPR extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.410";

	/**
	 * Constructor.
	 */
	public SWIFFTX384andWinternitzOTS_2withSPR() {
	    super(OID, new SWIFFTX384(), new WinternitzOTS(2), true);
	}
    }

    /**
     * CMSSKeyPairGenerator with SWIFFTX384 message digest, Winternitz OTS with
     * parameter w=3, SWIFFTX224PRNG and SPR
     */
    public static class SWIFFTX384andWinternitzOTS_3withSPR extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.411";

	/**
	 * Constructor.
	 */
	public SWIFFTX384andWinternitzOTS_3withSPR() {
	    super(OID, new SWIFFTX384(), new WinternitzOTS(3), true);
	}
    }

    /**
     * CMSSKeyPairGenerator with SWIFFTX384 message digest, Winternitz OTS with
     * parameter w=4, SWIFFTX224PRNG and SPR
     */
    public static class SWIFFTX384andWinternitzOTS_4withSPR extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.112";

	/**
	 * Constructor.
	 */
	public SWIFFTX384andWinternitzOTS_4withSPR() {
	    super(OID, new SWIFFTX384(), new WinternitzOTS(4), true);
	}
    }

    /**
     * CMSSKeyPairGenerator with SWIFFTX512 message digest, Winternitz OTS with
     * parameter w=1, SWIFFTX224PRNG and SPR
     */
    public static class SWIFFTX512andWinternitzOTS_1withSPR extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.413";

	/**
	 * Constructor.
	 */
	public SWIFFTX512andWinternitzOTS_1withSPR() {
	    super(OID, new SWIFFTX512(), new WinternitzOTS(1), true);
	}
    }

    /**
     * CMSSKeyPairGenerator with SWIFFTX512 message digest, Winternitz OTS with
     * parameter w=2, SWIFFTX224PRNG and SPR
     */
    public static class SWIFFTX512andWinternitzOTS_2withSPR extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.414";

	/**
	 * Constructor.
	 */
	public SWIFFTX512andWinternitzOTS_2withSPR() {
	    super(OID, new SWIFFTX512(), new WinternitzOTS(2), true);
	}
    }

    /**
     * CMSSKeyPairGenerator with SWIFFTX512 message digest, Winternitz OTS with
     * parameter w=3, SWIFFTX224PRNG and SPR
     */
    public static class SWIFFTX512andWinternitzOTS_3withSPR extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.415";

	/**
	 * Constructor.
	 */
	public SWIFFTX512andWinternitzOTS_3withSPR() {
	    super(OID, new SWIFFTX512(), new WinternitzOTS(3), true);
	}
    }

    /**
     * CMSSKeyPairGenerator with SWIFFTX512 message digest, Winternitz OTS with
     * parameter w=4, SWIFFTX224PRNG and SPR
     */
    public static class SWIFFTX512andWinternitzOTS_4withSPR extends
	    CMSSKeyPairGenerator {

	/**
	 * The OID of the algorithm.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.416";

	/**
	 * Constructor.
	 */
	public SWIFFTX512andWinternitzOTS_4withSPR() {
	    super(OID, new SWIFFTX512(), new WinternitzOTS(4), true);
	}
    }

    
  //LM-OTS
	

	/**
	 * CMSSKeyPairGenerator with SHA1 message digest, LMOTS OTS, and SHA1PRNG
	 */
	public static class SHA1andLMOTS extends CMSSKeyPairGenerator {

		/**
		 * The OID of the algorithm.
		 */
		public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.117";

		/**
		 * Constructor.
		 */
		public SHA1andLMOTS() {
			super(OID, new SHA1(), new LMOTS(), false);
		}
	}


	/**
	 * CMSSKeyPairGenerator with SHA256 message digest, LMOTS OTS, and SHA1PRNG
	 */
	public static class SHA256andLMOTS extends CMSSKeyPairGenerator {

		/**
		 * The OID of the algorithm.
		 */
		public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.118";

		/**
		 * Constructor.
		 */
		public SHA256andLMOTS() {
			super(OID, new SHA256(), new LMOTS(), false);
		}
	}


	/**
	 * CMSSKeyPairGenerator with SHA384 message digest, LMOTS OTS, and SHA1PRNG
	 */
	public static class SHA384andLMOTS extends CMSSKeyPairGenerator {

		/**
		 * The OID of the algorithm.
		 */
		public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.119";

		/**
		 * Constructor.
		 */
		public SHA384andLMOTS() {
			super(OID, new SHA384(), new LMOTS(), false);
		}
	}

	/**
	 * CMSSKeyPairGenerator with SHA512 message digest, LMOTS OTS, and SHA1PRNG
	 */
	public static class SHA512andLMOTS extends CMSSKeyPairGenerator {

		/**
		 * The OID of the algorithm.
		 */
		public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.120";

		/**
		 * Constructor.
		 */
		public SHA512andLMOTS() {
			super(OID, new SHA512(), new LMOTS(), false);
		}
	}


	/**
	 * CMSSKeyPairGenerator with SWIFFTX224 message digest, LMOTS OTS, and SWIFFTX224PRNG
	 */
	public static class SWIFFTX224andLMOTS extends CMSSKeyPairGenerator {

		/**
		 * The OID of the algorithm.
		 */
		public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.121";

		/**
		 * Constructor.
		 */
		public SWIFFTX224andLMOTS() {
			super(OID, new SWIFFTX224(), new LMOTS(), false);
		}
	}

	/**
	 * CMSSKeyPairGenerator with SWIFFTX256 message digest, LMOTS OTS, and SWIFFTX256PRNG
	 */
	public static class SWIFFTX256andLMOTS extends CMSSKeyPairGenerator {

		/**
		 * The OID of the algorithm.
		 */
		public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.122";

		/**
		 * Constructor.
		 */
		public SWIFFTX256andLMOTS() {
			super(OID, new SWIFFTX256(), new LMOTS(), false);
		}
	}

	/**
	 * CMSSKeyPairGenerator with SWIFFTX384 message digest, LMOTS OTS, and SWIFFTX384PRNG
	 */
	public static class SWIFFTX384andLMOTS extends CMSSKeyPairGenerator {

		/**
		 * The OID of the algorithm.
		 */
		public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.123";

		/**
		 * Constructor.
		 */
		public SWIFFTX384andLMOTS() {
			super(OID, new SWIFFTX384(), new LMOTS(), false);
		}
	}

	/**
	 * CMSSKeyPairGenerator with SWIFFTX512 message digest, LMOTS OTS, and SWIFFTX512PRNG
	 */
	public static class SWIFFTX512andLMOTS extends CMSSKeyPairGenerator {

		/**
		 * The OID of the algorithm.
		 */
		public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.124";

		/**
		 * Constructor.
		 */
		public SWIFFTX512andLMOTS() {
			super(OID, new SWIFFTX512(), new LMOTS(), false);
		}
	}    
    
	
	    /**
	     * CMSSKeyPairGenerator with SHA1 message digest, Winternitz2 OTS with
	     * parameter w=2, and SHA1PRNG
	     */
	    public static class SHA1andWinternitzPRFOTS_2 extends CMSSKeyPairGenerator {

		/**
		 * The OID of the algorithm.
		 */
		public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.40";

		/**
		 * Constructor.
		 */
		public SHA1andWinternitzPRFOTS_2() {
		    super(OID, new SHA1(), new WinternitzPRFOTS(2),false);
		}
	    }

	    /**
	     * CMSSKeyPairGenerator with SHA1 message digest, Winternitz2 OTS with
	     * parameter w=3, and SHA1PRNG
	     */
	    public static class SHA1andWinternitzPRFOTS_3 extends CMSSKeyPairGenerator {

		/**
		 * The OID of the algorithm.
		 */
		public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.41";

		/**
		 * Constructor.
		 */
		public SHA1andWinternitzPRFOTS_3() {
		    super(OID, new SHA1(), new WinternitzPRFOTS(3),false);
		}
	    }

	    /**
	     * CMSSKeyPairGenerator with SHA1 message digest, Winternitz2 OTS with
	     * parameter w=4, and SHA1PRNG
	     */
	    public static class SHA1andWinternitzPRFOTS_4 extends CMSSKeyPairGenerator {

		/**
		 * The OID of the algorithm.
		 */
		public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.42";

		/**
		 * Constructor.
		 */
		public SHA1andWinternitzPRFOTS_4() {
		    super(OID, new SHA1(), new WinternitzPRFOTS(4),false);
		}
	    }
	       
	    /**
	     * CMSSKeyPairGenerator with SHA1 message digest, Winternitz2 OTS with
	     * parameter w=5, and SHA1PRNG
	     */
	    public static class SHA1andWinternitzPRFOTS_5 extends CMSSKeyPairGenerator {

		/**
		 * The OID of the algorithm.
		 */
		public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.43";

		/**
		 * Constructor.
		 */
		public SHA1andWinternitzPRFOTS_5() {
		    super(OID, new SHA1(), new WinternitzPRFOTS(5),false);
		}
	    }
	    
	    /**
	     * CMSSKeyPairGenerator with SHA1 message digest, Winternitz2 OTS with
	     * parameter w=8, and SHA1PRNG
	     */
	    public static class SHA1andWinternitzPRFOTS_8 extends CMSSKeyPairGenerator {

		/**
		 * The OID of the algorithm.
		 */
		public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.44";

		/**
		 * Constructor.
		 */
		public SHA1andWinternitzPRFOTS_8() {
		    super(OID, new SHA1(), new WinternitzPRFOTS(8),false);
		}
	    }
	    
	    /**
	     * CMSSKeyPairGenerator with SHA1 message digest, Winternitz2 OTS with
	     * parameter w=16, and SHA1PRNG
	     */
	    public static class SHA1andWinternitzPRFOTS_16 extends CMSSKeyPairGenerator {

		/**
		 * The OID of the algorithm.
		 */
		public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.45";

		/**
		 * Constructor.
		 */
		public SHA1andWinternitzPRFOTS_16() {
		    super(OID, new SHA1(), new WinternitzPRFOTS(16),false);
		}
	    }

	    /**
	     * CMSSKeyPairGenerator with SHA1 message digest, Winternitz2 OTS with
	     * parameter w=16, and SHA1PRNG
	     */
	    public static class SHA1andWinternitzPRFOTS_20 extends CMSSKeyPairGenerator {

		/**
		 * The OID of the algorithm.
		 */
		public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.45";

		/**
		 * Constructor.
		 */
		public SHA1andWinternitzPRFOTS_20() {
		    super(OID, new SHA1(), new WinternitzPRFOTS(20),false);
		}
	    }

	    
	    
	    /**
	     * CMSSKeyPairGenerator with SHA256 message digest, Winternitz2 OTS with
	     * parameter w=2, and SHA1PRNG
	     */
	    public static class SHA256andWinternitzPRFOTS_2 extends CMSSKeyPairGenerator {

		/**
		 * The OID of the algorithm.
		 */
		public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.46";

		/**
		 * Constructor.
		 */
		public SHA256andWinternitzPRFOTS_2() {
		    super(OID, new SHA256(), new WinternitzPRFOTS(2),false);
		}
	    }

	    /**
	     * CMSSKeyPairGenerator with SHA256 message digest, Winternitz2 OTS with
	     * parameter w=3, and SHA1PRNG
	     */
	    public static class SHA256andWinternitzPRFOTS_3 extends CMSSKeyPairGenerator {

		/**
		 * The OID of the algorithm.
		 */
		public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.47";

		/**
		 * Constructor.
		 */
		public SHA256andWinternitzPRFOTS_3() {
		    super(OID, new SHA256(), new WinternitzPRFOTS(3),false);
		}
	    }

	    /**
	     * CMSSKeyPairGenerator with SHA256 message digest, Winternitz2 OTS with
	     * parameter w=4, and SHA1PRNG
	     */
	    public static class SHA256andWinternitzPRFOTS_4 extends CMSSKeyPairGenerator {

		/**
		 * The OID of the algorithm.
		 */
		public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.48";

		/**
		 * Constructor.
		 */
		public SHA256andWinternitzPRFOTS_4() {
		    super(OID, new SHA256(), new WinternitzPRFOTS(4),false);
		}
	    }
	    
	    /**
	     * CMSSKeyPairGenerator with SHA256 message digest, Winternitz2 OTS with
	     * parameter w=5, and SHA1PRNG
	     */
	    public static class SHA256andWinternitzPRFOTS_5 extends CMSSKeyPairGenerator {

		/**
		 * The OID of the algorithm.
		 */
		public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.49";

		/**
		 * Constructor.
		 */
		public SHA256andWinternitzPRFOTS_5() {
		    super(OID, new SHA256(), new WinternitzPRFOTS(5),false);
		}
	    }

	    /**
	     * CMSSKeyPairGenerator with SHA256 message digest, Winternitz2 OTS with
	     * parameter w=8, and SHA1PRNG
	     */
	    public static class SHA256andWinternitzPRFOTS_8 extends CMSSKeyPairGenerator {

		/**
		 * The OID of the algorithm.
		 */
		public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.50";

		/**
		 * Constructor.
		 */
		public SHA256andWinternitzPRFOTS_8() {
		    super(OID, new SHA256(), new WinternitzPRFOTS(8),false);
		}
	    }

	    /**
	     * CMSSKeyPairGenerator with SHA256 message digest, Winternitz2 OTS with
	     * parameter w=16, and SHA1PRNG
	     */
	    public static class SHA256andWinternitzPRFOTS_16 extends CMSSKeyPairGenerator {

		/**
		 * The OID of the algorithm.
		 */
		public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.51";

		/**
		 * Constructor.
		 */
		public SHA256andWinternitzPRFOTS_16() {
		    super(OID, new SHA256(), new WinternitzPRFOTS(16),false);
		}
	    }

	    
	    /**
	     * CMSSKeyPairGenerator with SHA384 message digest, Winternitz2 OTS with
	     * parameter w=2, and SHA1PRNG
	     */
	    public static class SHA384andWinternitzPRFOTS_2 extends CMSSKeyPairGenerator {

		/**
		 * The OID of the algorithm.
		 */
		public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.52";

		/**
		 * Constructor.
		 */
		public SHA384andWinternitzPRFOTS_2() {
		    super(OID, new SHA384(), new WinternitzPRFOTS(2),false);
		}
	    }

	    /**
	     * CMSSKeyPairGenerator with SHA384 message digest, Winternitz2 OTS with
	     * parameter w=3, and SHA1PRNG
	     */
	    public static class SHA384andWinternitzPRFOTS_3 extends CMSSKeyPairGenerator {

		/**
		 * The OID of the algorithm.
		 */
		public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.53";

		/**
		 * Constructor.
		 */
		public SHA384andWinternitzPRFOTS_3() {
		    super(OID, new SHA384(), new WinternitzPRFOTS(3),false);
		}
	    }

	    /**
	     * CMSSKeyPairGenerator with SHA384 message digest, Winternitz2 OTS with
	     * parameter w=4, and SHA1PRNG
	     */
	    public static class SHA384andWinternitzPRFOTS_4 extends CMSSKeyPairGenerator {

		/**
		 * The OID of the algorithm.
		 */
		public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.54";

		/**
		 * Constructor.
		 */
		public SHA384andWinternitzPRFOTS_4() {
		    super(OID, new SHA384(), new WinternitzPRFOTS(4),false);
		}
	    }
	    
	    /**
	     * CMSSKeyPairGenerator with SHA384 message digest, Winternitz2 OTS with
	     * parameter w=5, and SHA1PRNG
	     */
	    public static class SHA384andWinternitzPRFOTS_5 extends CMSSKeyPairGenerator {

		/**
		 * The OID of the algorithm.
		 */
		public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.55";

		/**
		 * Constructor.
		 */
		public SHA384andWinternitzPRFOTS_5() {
		    super(OID, new SHA384(), new WinternitzPRFOTS(5),false);
		}
	    }

	    /**
	     * CMSSKeyPairGenerator with SHA384 message digest, Winternitz2 OTS with
	     * parameter w=8, and SHA1PRNG
	     */
	    public static class SHA384andWinternitzPRFOTS_8 extends CMSSKeyPairGenerator {

		/**
		 * The OID of the algorithm.
		 */
		public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.56";

		/**
		 * Constructor.
		 */
		public SHA384andWinternitzPRFOTS_8() {
		    super(OID, new SHA384(), new WinternitzPRFOTS(8),false);
		}
	    }

	    /**
	     * CMSSKeyPairGenerator with SHA384 message digest, Winternitz2 OTS with
	     * parameter w=16, and SHA1PRNG
	     */
	    public static class SHA384andWinternitzPRFOTS_16 extends CMSSKeyPairGenerator {

		/**
		 * The OID of the algorithm.
		 */
		public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.57";

		/**
		 * Constructor.
		 */
		public SHA384andWinternitzPRFOTS_16() {
		    super(OID, new SHA384(), new WinternitzPRFOTS(16),false);
		}
	    }

	    
	    /**
	     * CMSSKeyPairGenerator with SHA512 message digest, Winternitz2 OTS with
	     * parameter w=2, and SHA1PRNG
	     */
	    public static class SHA512andWinternitzPRFOTS_2 extends CMSSKeyPairGenerator {

		/**
		 * The OID of the algorithm.
		 */
		public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.58";

		/**
		 * Constructor.
		 */
		public SHA512andWinternitzPRFOTS_2() {
		    super(OID, new SHA512(), new WinternitzPRFOTS(2),false);
		}
	    }

	    /**
	     * CMSSKeyPairGenerator with SHA512 message digest, Winternitz2 OTS with
	     * parameter w=3, and SHA1PRNG
	     */
	    public static class SHA512andWinternitzPRFOTS_3 extends CMSSKeyPairGenerator {

		/**
		 * The OID of the algorithm.
		 */
		public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.59";

		/**
		 * Constructor.
		 */
		public SHA512andWinternitzPRFOTS_3() {
		    super(OID, new SHA512(), new WinternitzPRFOTS(3),false);
		}
	    }

	    /**
	     * CMSSKeyPairGenerator with SHA512 message digest, Winternitz2 OTS with
	     * parameter w=4, and SHA1PRNG
	     */
	    public static class SHA512andWinternitzPRFOTS_4 extends CMSSKeyPairGenerator {

		/**
		 * The OID of the algorithm.
		 */
		public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.60";

		/**
		 * Constructor.
		 */
		public SHA512andWinternitzPRFOTS_4() {
		    super(OID, new SHA512(), new WinternitzPRFOTS(4),false);
		}
	    }
	    
	    /**
	     * CMSSKeyPairGenerator with SHA512 message digest, Winternitz2 OTS with
	     * parameter w=5, and SHA1PRNG
	     */
	    public static class SHA512andWinternitzPRFOTS_5 extends CMSSKeyPairGenerator {

		/**
		 * The OID of the algorithm.
		 */
		public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.61";

		/**
		 * Constructor.
		 */
		public SHA512andWinternitzPRFOTS_5() {
		    super(OID, new SHA512(), new WinternitzPRFOTS(5),false);
		}
	    }

	    /**
	     * CMSSKeyPairGenerator with SHA512 message digest, Winternitz2 OTS with
	     * parameter w=8, and SHA1PRNG
	     */
	    public static class SHA512andWinternitzPRFOTS_8 extends CMSSKeyPairGenerator {

		/**
		 * The OID of the algorithm.
		 */
		public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.62";

		/**
		 * Constructor.
		 */
		public SHA512andWinternitzPRFOTS_8() {
		    super(OID, new SHA512(), new WinternitzPRFOTS(8),false);
		}
	    }

	    /**
	     * CMSSKeyPairGenerator with SHA512 message digest, Winternitz2 OTS with
	     * parameter w=16, and SHA1PRNG
	     */
	    public static class SHA512andWinternitzPRFOTS_16 extends CMSSKeyPairGenerator {

		/**
		 * The OID of the algorithm.
		 */
		public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2.63";

		/**
		 * Constructor.
		 */
		public SHA512andWinternitzPRFOTS_16() {
		    super(OID, new SHA512(), new WinternitzPRFOTS(16),false);
		}
	    }

	    
    // //////////////////////////////////////////////////////////////////////////////

    /**
     * Constructor.
     * 
     * @param oidString
     *                the OID string identifying the algorithm
     * @param md
     *                the message digest used to build the authentication trees
     *                and for the OTS
     * @param ots
     *                the underlying OTS
     * @param useSpr
     *                use SPR-CMSS (true) or not (false)
     */
    protected CMSSKeyPairGenerator(String oidString, MessageDigest md,
	    OTS ots, boolean useSpr) {
	this.oidString = oidString;
	this.md = md;
	mdLength = md.getDigestLength();
	rng = new FIPS_186_2_PRNG();
	rng.initialize(md);
	ots.init(md, rng);
	this.ots = ots;
	this.useSpr = useSpr;
    }

    /**
     * Initialize the key pair generator.
     * 
     * @param heightOfTrees
     *                the height of the authentication trees
     * @param secureRandom
     *                the PRNG used for key generation
     */
    public void initialize(int heightOfTrees, SecureRandom secureRandom) {
	int seedSize = md.getDigestLength();
	initialize(heightOfTrees, seedSize, secureRandom);
    }

    /**
     * Initialize the key pair generator.
     * 
     * @param params
     *                an instance of {@link CMSSParameterSpec}
     * @param secureRandom
     *                the PRNG used for key generation
     * @see CMSSParameterSpec
     * @throws InvalidAlgorithmParameterException
     *                 if the given AlgorithmParameterSpec object is not an
     *                 instance of {@link CMSSParameterSpec}
     */
    public void initialize(AlgorithmParameterSpec params,
	    SecureRandom secureRandom)
	    throws InvalidAlgorithmParameterException {

	if (!(params instanceof CMSSParameterSpec)) {
	    throw new InvalidAlgorithmParameterException(
		    "Not an instance of CMSS2ParameterSpec.");
	}

	int heightOfTrees = ((CMSSParameterSpec) params).getHeightOfTrees();
	int seedSize = ((CMSSParameterSpec) params).getSeedSize();

	initialize(heightOfTrees, seedSize, secureRandom);
    }

    /**
     * Initialize the key pair generator.
     * 
     * @param heightOfTrees
     *                the height of the authentication trees
     * @param seedSize
     *                the bit length of the seed for the PRNG
     * @param sr
     *                the PRNG used for key pair generation
     */
    private void initialize(int heightOfTrees, int seedSize, SecureRandom sr) {
	if (mdLength > seedSize) {
	    seedSize = mdLength;
	}
	if (sr != null) {
	    this.sr = sr;
	} else if (this.sr == null) {
	    this.sr = Registry.getSecureRandom();
	}

	seeds = new byte[3][];
	seeds[0] = this.sr.generateSeed(seedSize);
	seeds[1] = this.sr.generateSeed(seedSize);
	seeds[2] = new byte[seedSize];

	this.heightOfTrees = heightOfTrees;

	initialized = true;
    }

    /**
     * This method is called by {@link #generateKeyPair()} in case that no other
     * initialization method has been called by the user. It initializes the key
     * pair generator with default parameters.
     */
    private void initializeDefault() {
	CMSSParameterSpec defaultParams = new CMSSParameterSpec();
	initialize(defaultParams.getHeightOfTrees(), defaultParams
		.getSeedSize(), null);
    }

    /**
     * Generate a CMSS2 key pair. The public key is an instance of
     * {@link CMSS2PublicKey}, the private key is an instance of
     * {@link CMSS2PrivateKey}.
     * 
     * @return the generated key pair
     * @see CMSS2PublicKey
     * @see CMSS2PrivateKey
     */
    public KeyPair genKeyPair() {
	if (!initialized) {
	    initializeDefault();
	}
	int K = 2;
	if (heightOfTrees % 2 != 0)
	    K += 1;

	BDSAuthPath[] authPath = new BDSAuthPath[3];

	byte[][][] masks = null;
	NodeCalc subNc, mainNc;

	if (useSpr) {
	    int heightOfKeyTree = getKeyTreeHeight(ots);
	    masks = generateMasks(md.getDigestLength(),
		    2 * (heightOfTrees + heightOfKeyTree));
	    byte[][][] subMasks = new byte[masks.length / 2][][];
	    System.arraycopy(masks, 0, subMasks, 0, subMasks.length);
	    byte[][][] mainMasks = new byte[masks.length / 2][][];
	    System.arraycopy(masks, subMasks.length, mainMasks, 0,
		    mainMasks.length);
	    subNc = new SPRNodeCalc(md, subMasks, md.getDigestLength());
	    mainNc = new SPRNodeCalc(md, mainMasks, md.getDigestLength());
	} else {
	    subNc = new CRNodeCalc(md);
	    mainNc = new CRNodeCalc(md);
	}

	/* generate the main tree */
	authPath[0] = new BDSAuthPath(heightOfTrees, K);
	authPath[0].setup(md, ots, rng, mainNc);
	byte[] maintreeRoot = authPath[0].initialize(ByteUtils.clone(seeds[0]));

	/* generate the first sub tree */
	authPath[1] = new BDSAuthPath(heightOfTrees, K);
	authPath[1].setup(md, ots, rng, subNc);
	byte[] seedSub = ByteUtils.clone(seeds[1]);
	byte[] subtreeRoot = authPath[1].initialize(seedSub);

	/* get seed for next subtree and setup initialization */
	seeds[2] = ByteUtils.clone(seedSub);
	// WARUM???
	rng.nextSeed(seeds[2]);
	//
	authPath[2] = new BDSAuthPath(heightOfTrees, K);
	authPath[2].setup(md, ots, rng, subNc);
	authPath[2].initializationSetup();

	/* sign root of first subtree */
	byte[] otsSeed = rng.nextSeed(seeds[0]);
	ots.generateSignatureKey(otsSeed);
	byte[] subtreeRootSig = ots.sign(subtreeRoot);

	byte[] maintreeOTSVerificationKey;
	if (ots.canComputeVerificationKeyFromSignature()) {
	    maintreeOTSVerificationKey = null;
	    authPath[0].setLeftLeaf(mainNc.getLeaf(ots.computeVerificationKey(
		    subtreeRoot, subtreeRootSig)));
	} else {
	    ots.generateVerificationKey();
	    maintreeOTSVerificationKey = ots.getVerificationKey();
	    authPath[0].setLeftLeaf(mainNc.getLeaf(maintreeOTSVerificationKey));
	}

	CMSSPublicKey pubKey = new CMSSPublicKey(oidString, maintreeRoot,
		masks);
	CMSSPrivateKey privKey = new CMSSPrivateKey(oidString, 0, 0,
		heightOfTrees, seeds, authPath, 0, subtreeRootSig,
		maintreeOTSVerificationKey, masks);

	return new KeyPair(pubKey, privKey);
    }

    /**
     * When SPR Hash functions are in use, the height of the trees grows
     * depending on the ots verification key length. This method calculates the
     * number the height grows by.
     * 
     * @param ots
     *                the ots, that is used
     * @return the added height of the trees due to use of SPR
     */
    private int getKeyTreeHeight(OTS ots) {
	int t = ots.getVerificationKeyLength() / mdLength;
	return IntegerFunctions.ceilLog(t);
    }

    /**
     * This method generates 2 * <code>height</code> random numbers each of
     * length <code>length</code> to be used as masks for the SPR-Trees and
     * returns them in a three dimensional array. The first dimension ist
     * <code>height</code>, the second is 2 (left and right) and the third is
     * <code>length</code>.
     * 
     * @param length
     *                the length of the random numbers
     * @param height
     *                the height of the tree
     * @return the three dimensional byte array containing the random numbers
     */
    private byte[][][] generateMasks(int length, int height) {
	PRNG rng = new FIPS_186_2_PRNG();
	rng.initialize(md);
	byte[] seed = Registry.getSecureRandom().generateSeed(length);
	byte[][][] masks = new byte[height][2][];
	byte[] currentSeed = ByteUtils.clone(seed);
	for (int i = 0; i < masks.length; i++) {
	    for (int j = 0; j < masks[i].length; j++) {
		masks[i][j] = rng.nextSeed(currentSeed);
	    }
	}

	return masks;
    }
}
