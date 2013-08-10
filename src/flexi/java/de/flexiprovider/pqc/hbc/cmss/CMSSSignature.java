package de.flexiprovider.pqc.hbc.cmss;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import de.flexiprovider.api.MessageDigest;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.api.Signature;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.exceptions.SignatureException;
import de.flexiprovider.api.keys.PrivateKey;
import de.flexiprovider.api.keys.PublicKey;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.util.ByteUtils;
import de.flexiprovider.common.util.LittleEndianConversions;
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
import de.flexiprovider.pqc.hbc.ots.BiBaOTS;
import de.flexiprovider.pqc.hbc.ots.LMOTS;
import de.flexiprovider.pqc.hbc.ots.OTS;
import de.flexiprovider.pqc.hbc.ots.WinternitzOTS;
import de.flexiprovider.pqc.hbc.ots.WinternitzPRFOTS;

/**
 * This class implements the CMSS2 signature scheme. The class extends the
 * SignatureSpi class. It is able to use the SPR hash functions as described in
 * E. Dahmen et al., "Digital Signatures Out of Second-Preimage Resistant Hash
 * Functions".
 * <p>
 * The CMSS2Signature can be used as follows:
 * <p>
 * <b>Signature generation:</b>
 * <p>
 * 1. generate KeySpec from encoded CMSS2 private key:<br/>
 * <tt>KeySpec privateKeySpec = new PKCS8EncodedKeySpec(encPrivateKey);</tt><br/>
 * 2. get instance of CMSS2 key factory:<br/>
 * <tt>KeyFactory keyFactory = KeyFactory.getInstance("CMSS2","FlexiPQC");</tt><br/>
 * 3. decode CMSS2 private key:<br/>
 * <tt>PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);</tt><br/>
 * 4. get instance of a CMSS2 signature:<br/>
 * <tt>Signature cmmsSig =
 * Signature.getInstance("SHA1andWinternitzOTS_1","FlexiPQC");</tt><br/>
 * 5. initialize signing:<br/>
 * <tt>cmssSig.initSign(privateKey);</tt><br/>
 * 6. sign message:<br/>
 * <tt>cmssSig.update(message.getBytes());<br/>
 * signature = cmssSig.sign();<br/>
 * return signature;</tt>
 * <p>
 * <b>Signature verification:</b>
 * <p>
 * 1. generate KeySpec from encoded CMSS2 public key:<br/>
 * <tt>KeySpec publicKeySpec = new X509EncodedKeySpec(encPublicKey);</tt><br/>
 * 2. decode CMSS2 public key:<br/>
 * <tt>PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);</tt><br/>
 * 3. initialize verifying:<br/>
 * <tt>cmssSig.initVerify(publicKey);</tt><br/>
 * 4. Verify the signature:<br/>
 * <tt>cmssSig.update(message.getBytes());<br/>
 * return cmssSig.verify(signature);</tt>
 * 
 * @author Elena Klintsevich
 * @author Martin D�ring
 * @see CMSS2KeyPairGenerator
 */
public class CMSSSignature extends Signature {

	// the OID of the algorithm
	private String oid;

	// the message digest used to build the authentication trees and for the OTS
	private MessageDigest md;

	// the length of the hash function output
	private int mdLength;

	// the one-time signature scheme
	private OTS ots;

	// the RNG used for key pair generation
	private PRNG rng;

	// the private key
	private CMSSPrivateKey privKey;

	// the public key
	private CMSSPublicKey pubKey;

	// the public key bytes
	private byte[] pubKeyBytes;

	// the ByteArrayOutputStream holding the messages
	private ByteArrayOutputStream baos;

	// the main tree index
	private int indexMain;

	// the current subtree index
	private int indexSub;

	// the seeds for key pair generation
	private byte[][] seeds;

	// an array of three authentication paths for the main tree, current subtree
	// and next subtree
	private BDSAuthPath[] authPath;
	private int activeSubtree;

	// the one-time signature of the root of the current subtree
	private byte[] subtreeRootSig;

	// the one-time verification key used to verify the rootSignature of the
	// subtree
	private byte[] maintreeOTSVerificationKey;

	// the height of the authentication trees
	private int heightOfTrees;

	// the number of leafs of each tree
	private int numLeafs;

	// way to compute parent nodes
	private NodeCalc mainNc, subNc;

	private boolean useSpr;

	// //////////////////////////////////////////////////////////////////////////////

	/*
	 * Inner classes providing concrete implementations of MerkleOTSSignature
	 * with a variety of message digests. index 0 for MerkleOTS, index1 - for
	 * CoronadoOTS
	 */

	/**
	 * CMSSSignature with SHA1 message digest, Winternitz OTS with parameter
	 * w=1, and SHA1PRNG
	 */
	public static class SHA1andWinternitzOTS_1 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA1andWinternitzOTS_1.OID;

		/**
		 * Constructor.
		 */
		public SHA1andWinternitzOTS_1() {
			super("1.3.6.1.4.1.8301.3.1.3.2.1", new SHA1(),
					new WinternitzOTS(1), false);
		}
	}

	/**
	 * CMSSSignature with SHA1 message digest, Winternitz OTS with parameter
	 * w=2, and SHA1PRNG
	 */
	public static class SHA1andWinternitzOTS_2 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA1andWinternitzOTS_2.OID;

		/**
		 * Constructor.
		 */
		public SHA1andWinternitzOTS_2() {
			super("1.3.6.1.4.1.8301.3.1.3.2.2", new SHA1(),
					new WinternitzOTS(2), false);
		}
	}

	/**
	 * CMSSSignature with SHA1 message digest, Winternitz OTS with parameter
	 * w=3, and SHA1PRNG
	 */
	public static class SHA1andWinternitzOTS_3 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA1andWinternitzOTS_3.OID;

		/**
		 * Constructor.
		 */
		public SHA1andWinternitzOTS_3() {
			super("1.3.6.1.4.1.8301.3.1.3.2.3", new SHA1(),
					new WinternitzOTS(3), false);
		}
	}

	/**
	 * CMSSSignature with SHA1 message digest, Winternitz OTS with parameter
	 * w=4, and SHA1PRNG
	 */
	public static class SHA1andWinternitzOTS_4 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA1andWinternitzOTS_4.OID;

		/**
		 * Constructor.
		 */
		public SHA1andWinternitzOTS_4() {
			super("1.3.6.1.4.1.8301.3.1.3.2.4", new SHA1(),
					new WinternitzOTS(4), false);
		}
	}

	/**
	 * CMSSSignature with SHA256 message digest, Winternitz OTS with parameter
	 * w=1, and SHA1PRNG
	 */
	public static class SHA256andWinternitzOTS_1 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA256andWinternitzOTS_1.OID;

		/**
		 * Constructor.
		 */
		public SHA256andWinternitzOTS_1() {
			super("1.3.6.1.4.1.8301.3.1.3.2.5", new SHA256(),
					new WinternitzOTS(1), false);
		}
	}

	/**
	 * CMSSSignature with SHA256 message digest, Winternitz OTS with parameter
	 * w=2, and SHA1PRNG
	 */
	public static class SHA256andWinternitzOTS_2 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA256andWinternitzOTS_2.OID;

		/**
		 * Constructor.
		 */
		public SHA256andWinternitzOTS_2() {
			super("1.3.6.1.4.1.8301.3.1.3.2.6", new SHA256(),
					new WinternitzOTS(2), false);
		}
	}

	/**
	 * CMSSSignature with SHA256 message digest, Winternitz OTS with parameter
	 * w=3, and SHA1PRNG
	 */
	public static class SHA256andWinternitzOTS_3 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA256andWinternitzOTS_3.OID;

		/**
		 * Constructor.
		 */
		public SHA256andWinternitzOTS_3() {
			super("1.3.6.1.4.1.8301.3.1.3.2.7", new SHA256(),
					new WinternitzOTS(3), false);
		}
	}

	/**
	 * CMSSSignature with SHA256 message digest, Winternitz OTS with parameter
	 * w=4, and SHA1PRNG
	 */
	public static class SHA256andWinternitzOTS_4 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA256andWinternitzOTS_4.OID;

		/**
		 * Constructor.
		 */
		public SHA256andWinternitzOTS_4() {
			super("1.3.6.1.4.1.8301.3.1.3.2.8", new SHA256(),
					new WinternitzOTS(4), false);
		}
	}

	/**
	 * CMSSSignature with SHA384 message digest, Winternitz OTS with parameter
	 * w=1, and SHA1PRNG
	 */
	public static class SHA384andWinternitzOTS_1 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA384andWinternitzOTS_1.OID;

		/**
		 * Constructor.
		 */
		public SHA384andWinternitzOTS_1() {
			super("1.3.6.1.4.1.8301.3.1.3.2.9", new SHA384(),
					new WinternitzOTS(1), false);
		}
	}

	/**
	 * CMSSSignature with SHA384 message digest, Winternitz OTS with parameter
	 * w=2, and SHA1PRNG
	 */
	public static class SHA384andWinternitzOTS_2 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA384andWinternitzOTS_2.OID;

		/**
		 * Constructor.
		 */
		public SHA384andWinternitzOTS_2() {
			super("1.3.6.1.4.1.8301.3.1.3.2.10", new SHA384(),
					new WinternitzOTS(2), false);
		}
	}

	/**
	 * CMSSSignature with SHA384 message digest, Winternitz OTS with parameter
	 * w=3, and SHA1PRNG
	 */
	public static class SHA384andWinternitzOTS_3 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA384andWinternitzOTS_3.OID;

		/**
		 * Constructor.
		 */
		public SHA384andWinternitzOTS_3() {
			super("1.3.6.1.4.1.8301.3.1.3.2.11", new SHA384(),
					new WinternitzOTS(3), false);
		}
	}

	/**
	 * CMSSSignature with SHA384 message digest, Winternitz OTS with parameter
	 * w=4, and SHA1PRNG
	 */
	public static class SHA384andWinternitzOTS_4 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA384andWinternitzOTS_4.OID;

		/**
		 * Constructor.
		 */
		public SHA384andWinternitzOTS_4() {
			super("1.3.6.1.4.1.8301.3.1.3.2.12", new SHA384(),
					new WinternitzOTS(4), false);
		}
	}

	/**
	 * CMSSSignature with SHA512 message digest, Winternitz OTS with parameter
	 * w=1, and SHA1PRNG
	 */
	public static class SHA512andWinternitzOTS_1 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA512andWinternitzOTS_1.OID;

		/**
		 * Constructor.
		 */
		public SHA512andWinternitzOTS_1() {
			super("1.3.6.1.4.1.8301.3.1.3.2.13", new SHA512(),
					new WinternitzOTS(1), false);
		}
	}

	/**
	 * CMSSSignature with SHA512 message digest, Winternitz OTS with parameter
	 * w=2, and SHA1PRNG
	 */
	public static class SHA512andWinternitzOTS_2 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA512andWinternitzOTS_2.OID;

		/**
		 * Constructor.
		 */
		public SHA512andWinternitzOTS_2() {
			super("1.3.6.1.4.1.8301.3.1.3.2.14", new SHA512(),
					new WinternitzOTS(2), false);
		}
	}

	/**
	 * CMSSSignature with SHA512 message digest, Winternitz OTS with parameter
	 * w=3, and SHA1PRNG
	 */
	public static class SHA512andWinternitzOTS_3 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA512andWinternitzOTS_3.OID;

		/**
		 * Constructor.
		 */
		public SHA512andWinternitzOTS_3() {
			super("1.3.6.1.4.1.8301.3.1.3.2.15", new SHA512(),
					new WinternitzOTS(3), false);
		}
	}

	/**
	 * CMSSSignature with SHA512 message digest, Winternitz OTS with parameter
	 * w=4, and SHA1PRNG
	 */
	public static class SHA512andWinternitzOTS_4 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA512andWinternitzOTS_4.OID;

		/**
		 * Constructor.
		 */
		public SHA512andWinternitzOTS_4() {
			super("1.3.6.1.4.1.8301.3.1.3.2.16", new SHA512(),
					new WinternitzOTS(4), false);
		}
	}

	/**
	 * CMSSSignature with SWIFFTX224 message digest, Winternitz OTS with
	 * parameter w=1, and SWIFFTX224PRNG
	 */
	public static class SWIFFTX224andWinternitzOTS_1 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SWIFFTX224andWinternitzOTS_1.OID;

		/**
		 * Constructor.
		 */
		public SWIFFTX224andWinternitzOTS_1() {
			super("1.3.6.1.4.1.8301.3.1.3.2.101", new SWIFFTX224(),
					new WinternitzOTS(1), false);
		}
	}

	/**
	 * CMSSSignature with SWIFFTX224 message digest, Winternitz OTS with
	 * parameter w=2, and SWIFFTX224PRNG
	 */
	public static class SWIFFTX224andWinternitzOTS_2 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SWIFFTX224andWinternitzOTS_2.OID;

		/**
		 * Constructor.
		 */
		public SWIFFTX224andWinternitzOTS_2() {
			super("1.3.6.1.4.1.8301.3.1.3.2.102", new SWIFFTX224(),
					new WinternitzOTS(2), false);
		}
	}

	/**
	 * CMSSSignature with SWIFFTX224 message digest, Winternitz OTS with
	 * parameter w=3, and SWIFFTX224PRNG
	 */
	public static class SWIFFTX224andWinternitzOTS_3 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SWIFFTX224andWinternitzOTS_3.OID;

		/**
		 * Constructor.
		 */
		public SWIFFTX224andWinternitzOTS_3() {
			super("1.3.6.1.4.1.8301.3.1.3.2.103", new SWIFFTX224(),
					new WinternitzOTS(3), false);
		}
	}

	/**
	 * CMSSSignature with SWIFFTX224 message digest, Winternitz OTS with
	 * parameter w=4, and SWIFFTX224PRNG
	 */
	public static class SWIFFTX224andWinternitzOTS_4 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SWIFFTX224andWinternitzOTS_4.OID;

		/**
		 * Constructor.
		 */
		public SWIFFTX224andWinternitzOTS_4() {
			super("1.3.6.1.4.1.8301.3.1.3.2.104", new SWIFFTX224(),
					new WinternitzOTS(4), false);
		}
	}

	/**
	 * CMSSSignature with SWIFFTX256 message digest, Winternitz OTS with
	 * parameter w=1, and SWIFFTX256PRNG
	 */
	public static class SWIFFTX256andWinternitzOTS_1 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SWIFFTX256andWinternitzOTS_1.OID;

		/**
		 * Constructor.
		 */
		public SWIFFTX256andWinternitzOTS_1() {
			super("1.3.6.1.4.1.8301.3.1.3.2.105", new SWIFFTX256(),
					new WinternitzOTS(1), false);
		}
	}

	/**
	 * CMSSSignature with SWIFFTX256 message digest, Winternitz OTS with
	 * parameter w=2, and SWIFFTX256PRNG
	 */
	public static class SWIFFTX256andWinternitzOTS_2 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SWIFFTX256andWinternitzOTS_2.OID;

		/**
		 * Constructor.
		 */
		public SWIFFTX256andWinternitzOTS_2() {
			super("1.3.6.1.4.1.8301.3.1.3.2.106", new SWIFFTX256(),
					new WinternitzOTS(2), false);
		}
	}

	/**
	 * CMSSSignature with SWIFFTX256 message digest, Winternitz OTS with
	 * parameter w=3, and SWIFFTX256PRNG
	 */
	public static class SWIFFTX256andWinternitzOTS_3 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SWIFFTX256andWinternitzOTS_3.OID;

		/**
		 * Constructor.
		 */
		public SWIFFTX256andWinternitzOTS_3() {
			super("1.3.6.1.4.1.8301.3.1.3.2.107", new SWIFFTX256(),
					new WinternitzOTS(3), false);
		}
	}

	/**
	 * CMSSSignature with SWIFFTX256 message digest, Winternitz OTS with
	 * parameter w=4, and SWIFFTX256PRNG
	 */
	public static class SWIFFTX256andWinternitzOTS_4 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SWIFFTX256andWinternitzOTS_4.OID;

		/**
		 * Constructor.
		 */
		public SWIFFTX256andWinternitzOTS_4() {
			super("1.3.6.1.4.1.8301.3.1.3.2.108", new SWIFFTX256(),
					new WinternitzOTS(4), false);
		}
	}

	/**
	 * CMSSSignature with SWIFFTX384 message digest, Winternitz OTS with
	 * parameter w=1, and SWIFFTX384PRNG
	 */
	public static class SWIFFTX384andWinternitzOTS_1 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SWIFFTX384andWinternitzOTS_1.OID;

		/**
		 * Constructor.
		 */
		public SWIFFTX384andWinternitzOTS_1() {
			super("1.3.6.1.4.1.8301.3.1.3.2.109", new SWIFFTX384(),
					new WinternitzOTS(1), false);
		}
	}

	/**
	 * CMSSSignature with SWIFFTX384 message digest, Winternitz OTS with
	 * parameter w=2, and SWIFFTX384PRNG
	 */
	public static class SWIFFTX384andWinternitzOTS_2 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SWIFFTX384andWinternitzOTS_2.OID;

		/**
		 * Constructor.
		 */
		public SWIFFTX384andWinternitzOTS_2() {
			super("1.3.6.1.4.1.8301.3.1.3.2.110", new SWIFFTX384(),
					new WinternitzOTS(2), false);
		}
	}

	/**
	 * CMSSSignature with SWIFFTX384 message digest, Winternitz OTS with
	 * parameter w=3, and SWIFFTX384PRNG
	 */
	public static class SWIFFTX384andWinternitzOTS_3 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SWIFFTX384andWinternitzOTS_3.OID;

		/**
		 * Constructor.
		 */
		public SWIFFTX384andWinternitzOTS_3() {
			super("1.3.6.1.4.1.8301.3.1.3.2.111", new SWIFFTX384(),
					new WinternitzOTS(3), false);
		}
	}

	/**
	 * CMSSSignature with SWIFFTX384 message digest, Winternitz OTS with
	 * parameter w=4, and SWIFFTX384PRNG
	 */
	public static class SWIFFTX384andWinternitzOTS_4 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SWIFFTX384andWinternitzOTS_4.OID;

		/**
		 * Constructor.
		 */
		public SWIFFTX384andWinternitzOTS_4() {
			super("1.3.6.1.4.1.8301.3.1.3.2.112", new SWIFFTX384(),
					new WinternitzOTS(4), false);
		}
	}

	/**
	 * CMSSSignature with SWIFFTX512 message digest, Winternitz OTS with
	 * parameter w=1, and SWIFFTX512PRNG
	 */
	public static class SWIFFTX512andWinternitzOTS_1 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SWIFFTX512andWinternitzOTS_1.OID;

		/**
		 * Constructor.
		 */
		public SWIFFTX512andWinternitzOTS_1() {
			super("1.3.6.1.4.1.8301.3.1.3.2.113", new SWIFFTX512(),
					new WinternitzOTS(1), false);
		}
	}

	/**
	 * CMSSSignature with SWIFFTX512 message digest, Winternitz OTS with
	 * parameter w=2, and SWIFFTX512PRNG
	 */
	public static class SWIFFTX512andWinternitzOTS_2 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SWIFFTX512andWinternitzOTS_2.OID;

		/**
		 * Constructor.
		 */
		public SWIFFTX512andWinternitzOTS_2() {
			super("1.3.6.1.4.1.8301.3.1.3.2.114", new SWIFFTX512(),
					new WinternitzOTS(2), false);
		}
	}

	/**
	 * CMSSSignature with SWIFFTX512 message digest, Winternitz OTS with
	 * parameter w=3, and SWIFFTX512PRNG
	 */
	public static class SWIFFTX512andWinternitzOTS_3 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SWIFFTX512andWinternitzOTS_3.OID;

		/**
		 * Constructor.
		 */
		public SWIFFTX512andWinternitzOTS_3() {
			super("1.3.6.1.4.1.8301.3.1.3.2.115", new SWIFFTX512(),
					new WinternitzOTS(3), false);
		}
	}

	/**
	 * CMSSSignature with SWIFFTX512 message digest, Winternitz OTS with
	 * parameter w=4, and SWIFFTX512PRNG
	 */
	public static class SWIFFTX512andWinternitzOTS_4 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SWIFFTX512andWinternitzOTS_4.OID;

		/**
		 * Constructor.
		 */
		public SWIFFTX512andWinternitzOTS_4() {
			super("1.3.6.1.4.1.8301.3.1.3.2.116", new SWIFFTX512(),
					new WinternitzOTS(4), false);
		}
	}

	/**
	 * CMSSSignature with SHA1 message digest, BiBa OTS and SHA1PRNG
	 */
	public static class SHA1andBiBaOTS extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA1andBiBaOTS.OID;

		/**
		 * Constructor.
		 */
		public SHA1andBiBaOTS() {
			super("1.3.6.1.4.1.8301.3.1.3.2.201", new SHA1(), new BiBaOTS(),
					false);
		}
	}

	/**
	 * CMSSSignature with SHA1 message digest, BiBa OTS (security level 50) and
	 * SHA1PRNG
	 */
	public static class SHA1andBiBaOTS50 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA1andBiBaOTS.OID;

		/**
		 * Constructor.
		 */
		public SHA1andBiBaOTS50() {
			super("1.3.6.1.4.1.8301.3.1.3.2.203", new SHA1(), new BiBaOTS(
					new Integer(6), new Integer(994), null, null), false);
		}
	}

	/**
	 * CMSSSignature with SHA1 message digest, BiBa OTS (security level 80) and
	 * SHA1PRNG
	 */
	public static class SHA1andBiBaOTS80 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA1andBiBaOTS.OID;

		/**
		 * Constructor.
		 */
		public SHA1andBiBaOTS80() {
			super("1.3.6.1.4.1.8301.3.1.3.2.205", new SHA1(), new BiBaOTS(
					new Integer(11), new Integer(260), null, null), false);
		}
	}

	// SPR classes

	/**
	 * CMSSSignature with SHA1 message digest, BiBa OTS2 and SHA1PRNG with SPR
	 */
	public static class SHA1andBiBaOTSwithSPR extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA1andBiBaOTS.OID;

		/**
		 * Constructor.
		 */
		public SHA1andBiBaOTSwithSPR() {
			super("1.3.6.1.4.1.8301.3.1.3.2.202", new SHA1(), new BiBaOTS(),
					true);
		}
	}

	/**
	 * CMSSSignature with SHA1 message digest, BiBa OTS (security level 50) and
	 * SHA1PRNG with SPR
	 */
	public static class SHA1andBiBaOTS50withSPR extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA1andBiBaOTS.OID;

		/**
		 * Constructor.
		 */
		public SHA1andBiBaOTS50withSPR() {
			super("1.3.6.1.4.1.8301.3.1.3.2.204", new SHA1(), new BiBaOTS(
					new Integer(6), new Integer(994), null, null), true);
		}
	}

	/**
	 * CMSSSignature with SHA1 message digest, BiBa OTS (security level 80) and
	 * SHA1PRNG with SPR
	 */
	public static class SHA1andBiBaOTS80withSPR extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA1andBiBaOTS.OID;

		/**
		 * Constructor.
		 */
		public SHA1andBiBaOTS80withSPR() {
			super("1.3.6.1.4.1.8301.3.1.3.2.206", new SHA1(), new BiBaOTS(
					new Integer(11), new Integer(260), null, null), true);
		}
	}

	/**
	 * CMSSSignature with SHA1 message digest, Winternitz OTS with parameter
	 * w=1, SHA1PRNG and SPR
	 */
	public static class SHA1andWinternitzOTS_1withSPR extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA1andWinternitzOTS_1withSPR.OID;

		/**
		 * Constructor.
		 */
		public SHA1andWinternitzOTS_1withSPR() {
			super("1.3.6.1.4.1.8301.3.1.3.2.301", new SHA1(),
					new WinternitzOTS(1), true);
		}
	}

	/**
	 * CMSSSignature with SHA1 message digest, Winternitz OTS with parameter
	 * w=2, SHA1PRNG and SPR
	 */
	public static class SHA1andWinternitzOTS_2withSPR extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA1andWinternitzOTS_2withSPR.OID;

		/**
		 * Constructor.
		 */
		public SHA1andWinternitzOTS_2withSPR() {
			super("1.3.6.1.4.1.8301.3.1.3.2.302", new SHA1(),
					new WinternitzOTS(2), true);
		}
	}

	/**
	 * CMSSSignature with SHA1 message digest, Winternitz OTS with parameter
	 * w=3, SHA1PRNG and SPR
	 */
	public static class SHA1andWinternitzOTS_3withSPR extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA1andWinternitzOTS_3withSPR.OID;

		/**
		 * Constructor.
		 */
		public SHA1andWinternitzOTS_3withSPR() {
			super("1.3.6.1.4.1.8301.3.1.3.2.303", new SHA1(),
					new WinternitzOTS(3), true);
		}
	}

	/**
	 * CMSSSignature with SHA1 message digest, Winternitz OTS with parameter
	 * w=4, SHA1PRNG and SPR
	 */
	public static class SHA1andWinternitzOTS_4withSPR extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA1andWinternitzOTS_4withSPR.OID;

		/**
		 * Constructor.
		 */
		public SHA1andWinternitzOTS_4withSPR() {
			super("1.3.6.1.4.1.8301.3.1.3.2.304", new SHA1(),
					new WinternitzOTS(4), true);
		}
	}

	/**
	 * CMSSSignature with SHA256 message digest, Winternitz OTS with parameter
	 * w=1, SHA1PRNG and SPR
	 */
	public static class SHA256andWinternitzOTS_1withSPR extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA256andWinternitzOTS_1withSPR.OID;

		/**
		 * Constructor.
		 */
		public SHA256andWinternitzOTS_1withSPR() {
			super("1.3.6.1.4.1.8301.3.1.3.2.305", new SHA256(),
					new WinternitzOTS(1), true);
		}
	}

	/**
	 * CMSSSignature with SHA256 message digest, Winternitz OTS with parameter
	 * w=2, SHA1PRNG and SPR
	 */
	public static class SHA256andWinternitzOTS_2withSPR extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA256andWinternitzOTS_2withSPR.OID;

		/**
		 * Constructor.
		 */
		public SHA256andWinternitzOTS_2withSPR() {
			super("1.3.6.1.4.1.8301.3.1.3.2.306", new SHA256(),
					new WinternitzOTS(2), true);
		}
	}

	/**
	 * CMSSSignature with SHA256 message digest, Winternitz OTS with parameter
	 * w=3, SHA1PRNG and SPR
	 */
	public static class SHA256andWinternitzOTS_3withSPR extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA256andWinternitzOTS_3withSPR.OID;

		/**
		 * Constructor.
		 */
		public SHA256andWinternitzOTS_3withSPR() {
			super("1.3.6.1.4.1.8301.3.1.3.2.307", new SHA256(),
					new WinternitzOTS(3), true);
		}
	}

	/**
	 * CMSSSignature with SHA256 message digest, Winternitz OTS with parameter
	 * w=4, SHA1PRNG and SPR
	 */
	public static class SHA256andWinternitzOTS_4withSPR extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA256andWinternitzOTS_4withSPR.OID;

		/**
		 * Constructor.
		 */
		public SHA256andWinternitzOTS_4withSPR() {
			super("1.3.6.1.4.1.8301.3.1.3.2.308", new SHA256(),
					new WinternitzOTS(4), true);
		}
	}

	/**
	 * CMSSSignature with SHA384 message digest, Winternitz OTS with parameter
	 * w=1, SHA1PRNG and SPR
	 */
	public static class SHA384andWinternitzOTS_1withSPR extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA384andWinternitzOTS_1withSPR.OID;

		/**
		 * Constructor.
		 */
		public SHA384andWinternitzOTS_1withSPR() {
			super("1.3.6.1.4.1.8301.3.1.3.2.309", new SHA384(),
					new WinternitzOTS(1), true);
		}
	}

	/**
	 * CMSSSignature with SHA384 message digest, Winternitz OTS with parameter
	 * w=2, SHA1PRNG and SPR
	 */
	public static class SHA384andWinternitzOTS_2withSPR extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA384andWinternitzOTS_2withSPR.OID;

		/**
		 * Constructor.
		 */
		public SHA384andWinternitzOTS_2withSPR() {
			super("1.3.6.1.4.1.8301.3.1.3.2.310", new SHA384(),
					new WinternitzOTS(2), true);
		}
	}

	/**
	 * CMSSSignature with SHA384 message digest, Winternitz OTS with parameter
	 * w=3, SHA1PRNG and SPR
	 */
	public static class SHA384andWinternitzOTS_3withSPR extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA384andWinternitzOTS_3withSPR.OID;

		/**
		 * Constructor.
		 */
		public SHA384andWinternitzOTS_3withSPR() {
			super("1.3.6.1.4.1.8301.3.1.3.2.311", new SHA384(),
					new WinternitzOTS(3), true);
		}
	}

	/**
	 * CMSSSignature with SHA384 message digest, Winternitz OTS with parameter
	 * w=4, SHA1PRNG and SPR
	 */
	public static class SHA384andWinternitzOTS_4withSPR extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA384andWinternitzOTS_4withSPR.OID;

		/**
		 * Constructor.
		 */
		public SHA384andWinternitzOTS_4withSPR() {
			super("1.3.6.1.4.1.8301.3.1.3.2.312", new SHA384(),
					new WinternitzOTS(4), true);
		}
	}

	/**
	 * CMSSSignature with SHA512 message digest, Winternitz OTS with parameter
	 * w=1, SHA1PRNG and SPR
	 */
	public static class SHA512andWinternitzOTS_1withSPR extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA512andWinternitzOTS_1withSPR.OID;

		/**
		 * Constructor.
		 */
		public SHA512andWinternitzOTS_1withSPR() {
			super("1.3.6.1.4.1.8301.3.1.3.2.313", new SHA512(),
					new WinternitzOTS(1), true);
		}
	}

	/**
	 * CMSSSignature with SHA512 message digest, Winternitz OTS with parameter
	 * w=2, SHA1PRNG and SPR
	 */
	public static class SHA512andWinternitzOTS_2withSPR extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA512andWinternitzOTS_2withSPR.OID;

		/**
		 * Constructor.
		 */
		public SHA512andWinternitzOTS_2withSPR() {
			super("1.3.6.1.4.1.8301.3.1.3.2.314", new SHA512(),
					new WinternitzOTS(2), true);
		}
	}

	/**
	 * CMSSSignature with SHA512 message digest, Winternitz OTS with parameter
	 * w=3, SHA1PRNG and SPR
	 */
	public static class SHA512andWinternitzOTS_3withSPR extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA512andWinternitzOTS_3withSPR.OID;

		/**
		 * Constructor.
		 */
		public SHA512andWinternitzOTS_3withSPR() {
			super("1.3.6.1.4.1.8301.3.1.3.2.315", new SHA512(),
					new WinternitzOTS(3), true);
		}
	}

	/**
	 * CMSSSignature with SHA512 message digest, Winternitz OTS with parameter
	 * w=4, SHA1PRNG and SPR
	 */
	public static class SHA512andWinternitzOTS_4withSPR extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA512andWinternitzOTS_4withSPR.OID;

		/**
		 * Constructor.
		 */
		public SHA512andWinternitzOTS_4withSPR() {
			super("1.3.6.1.4.1.8301.3.1.3.2.316", new SHA512(),
					new WinternitzOTS(4), true);
		}
	}

	/**
	 * CMSSSignature with SWIFFTX224 message digest, Winternitz OTS with
	 * parameter w=1, SWIFFTX224PRNG and SPR
	 */
	public static class SWIFFTX224andWinternitzOTS_1withSPR extends
			CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SWIFFTX224andWinternitzOTS_1withSPR.OID;

		/**
		 * Constructor.
		 */
		public SWIFFTX224andWinternitzOTS_1withSPR() {
			super("1.3.6.1.4.1.8301.3.1.3.2.401", new SWIFFTX224(),
					new WinternitzOTS(1), true);
		}
	}

	/**
	 * CMSSSignature with SWIFFTX224 message digest, Winternitz OTS with
	 * parameter w=2, SWIFFTX224PRNG and SPR
	 */
	public static class SWIFFTX224andWinternitzOTS_2withSPR extends
			CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SWIFFTX224andWinternitzOTS_2withSPR.OID;

		/**
		 * Constructor.
		 */
		public SWIFFTX224andWinternitzOTS_2withSPR() {
			super("1.3.6.1.4.1.8301.3.1.3.2.402", new SWIFFTX224(),
					new WinternitzOTS(2), true);
		}
	}

	/**
	 * CMSSSignature with SWIFFTX224 message digest, Winternitz OTS with
	 * parameter w=3, SWIFFTX224PRNG and SPR
	 */
	public static class SWIFFTX224andWinternitzOTS_3withSPR extends
			CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SWIFFTX224andWinternitzOTS_3withSPR.OID;

		/**
		 * Constructor.
		 */
		public SWIFFTX224andWinternitzOTS_3withSPR() {
			super("1.3.6.1.4.1.8301.3.1.3.2.403", new SWIFFTX224(),
					new WinternitzOTS(3), true);
		}
	}

	/**
	 * CMSSSignature with SWIFFTX224 message digest, Winternitz OTS with
	 * parameter w=4, SWIFFTX224PRNG and SPR
	 */
	public static class SWIFFTX224andWinternitzOTS_4withSPR extends
			CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SWIFFTX224andWinternitzOTS_4withSPR.OID;

		/**
		 * Constructor.
		 */
		public SWIFFTX224andWinternitzOTS_4withSPR() {
			super("1.3.6.1.4.1.8301.3.1.3.2.404", new SWIFFTX224(),
					new WinternitzOTS(4), true);
		}
	}

	/**
	 * CMSSSignature with SWIFFTX256 message digest, Winternitz OTS with
	 * parameter w=1, SWIFFTX224PRNG and SPR
	 */
	public static class SWIFFTX256andWinternitzOTS_1withSPR extends
			CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SWIFFTX256andWinternitzOTS_1withSPR.OID;

		/**
		 * Constructor.
		 */
		public SWIFFTX256andWinternitzOTS_1withSPR() {
			super("1.3.6.1.4.1.8301.3.1.3.2.405", new SWIFFTX256(),
					new WinternitzOTS(1), true);
		}
	}

	/**
	 * CMSSSignature with SWIFFTX256 message digest, Winternitz OTS with
	 * parameter w=2, SWIFFTX224PRNG and SPR
	 */
	public static class SWIFFTX256andWinternitzOTS_2withSPR extends
			CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SWIFFTX256andWinternitzOTS_2withSPR.OID;

		/**
		 * Constructor.
		 */
		public SWIFFTX256andWinternitzOTS_2withSPR() {
			super("1.3.6.1.4.1.8301.3.1.3.2.406", new SWIFFTX256(),
					new WinternitzOTS(2), true);
		}
	}

	/**
	 * CMSSSignature with SWIFFTX256 message digest, Winternitz OTS with
	 * parameter w=3, SWIFFTX224PRNG and SPR
	 */
	public static class SWIFFTX256andWinternitzOTS_3withSPR extends
			CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SWIFFTX256andWinternitzOTS_3withSPR.OID;

		/**
		 * Constructor.
		 */
		public SWIFFTX256andWinternitzOTS_3withSPR() {
			super("1.3.6.1.4.1.8301.3.1.3.2.407", new SWIFFTX256(),
					new WinternitzOTS(3), true);
		}
	}

	/**
	 * CMSSSignature with SWIFFTX256 message digest, Winternitz OTS with
	 * parameter w=4, SWIFFTX224PRNG and SPR
	 */
	public static class SWIFFTX256andWinternitzOTS_4withSPR extends
			CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SWIFFTX256andWinternitzOTS_4withSPR.OID;

		/**
		 * Constructor.
		 */
		public SWIFFTX256andWinternitzOTS_4withSPR() {
			super("1.3.6.1.4.1.8301.3.1.3.2.408", new SWIFFTX256(),
					new WinternitzOTS(4), true);
		}
	}

	/**
	 * CMSSSignature with SWIFFTX384 message digest, Winternitz OTS with
	 * parameter w=1, SWIFFTX224PRNG and SPR
	 */
	public static class SWIFFTX384andWinternitzOTS_1withSPR extends
			CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SWIFFTX384andWinternitzOTS_1withSPR.OID;

		/**
		 * Constructor.
		 */
		public SWIFFTX384andWinternitzOTS_1withSPR() {
			super("1.3.6.1.4.1.8301.3.1.3.2.409", new SWIFFTX384(),
					new WinternitzOTS(1), true);
		}
	}

	/**
	 * CMSSSignature with SWIFFTX384 message digest, Winternitz OTS with
	 * parameter w=2, SWIFFTX224PRNG and SPR
	 */
	public static class SWIFFTX384andWinternitzOTS_2withSPR extends
			CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SWIFFTX384andWinternitzOTS_2withSPR.OID;

		/**
		 * Constructor.
		 */
		public SWIFFTX384andWinternitzOTS_2withSPR() {
			super("1.3.6.1.4.1.8301.3.1.3.2.410", new SWIFFTX384(),
					new WinternitzOTS(2), false);
		}
	}

	/**
	 * CMSSSignature with SWIFFTX384 message digest, Winternitz OTS with
	 * parameter w=3, SWIFFTX224PRNG and SPR
	 */
	public static class SWIFFTX384andWinternitzOTS_3withSPR extends
			CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SWIFFTX384andWinternitzOTS_3withSPR.OID;

		/**
		 * Constructor.
		 */
		public SWIFFTX384andWinternitzOTS_3withSPR() {
			super("1.3.6.1.4.1.8301.3.1.3.2.411", new SWIFFTX384(),
					new WinternitzOTS(3), true);
		}
	}

	/**
	 * CMSSSignature with SWIFFTX384 message digest, Winternitz OTS with
	 * parameter w=4, SWIFFTX224PRNG and SPR
	 */
	public static class SWIFFTX384andWinternitzOTS_4withSPR extends
			CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SWIFFTX384andWinternitzOTS_4withSPR.OID;

		/**
		 * Constructor.
		 */
		public SWIFFTX384andWinternitzOTS_4withSPR() {
			super("1.3.6.1.4.1.8301.3.1.3.2.412", new SWIFFTX384(),
					new WinternitzOTS(4), true);
		}
	}

	/**
	 * CMSSSignature with SWIFFTX512 message digest, Winternitz OTS with
	 * parameter w=1, SWIFFTX224PRNG and SPR
	 */
	public static class SWIFFTX512andWinternitzOTS_1withSPR extends
			CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SWIFFTX512andWinternitzOTS_1withSPR.OID;

		/**
		 * Constructor.
		 */
		public SWIFFTX512andWinternitzOTS_1withSPR() {
			super("1.3.6.1.4.1.8301.3.1.3.2.413", new SWIFFTX512(),
					new WinternitzOTS(1), true);
		}
	}

	/**
	 * CMSSSignature with SWIFFTX512 message digest, Winternitz OTS with
	 * parameter w=2, SWIFFTX224PRNG and SPR
	 */
	public static class SWIFFTX512andWinternitzOTS_2withSPR extends
			CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SWIFFTX512andWinternitzOTS_2withSPR.OID;

		/**
		 * Constructor.
		 */
		public SWIFFTX512andWinternitzOTS_2withSPR() {
			super("1.3.6.1.4.1.8301.3.1.3.2.414", new SWIFFTX512(),
					new WinternitzOTS(2), true);
		}
	}

	/**
	 * CMSSSignature with SWIFFTX512 message digest, Winternitz OTS with
	 * parameter w=3, SWIFFTX224PRNG and SPR
	 */
	public static class SWIFFTX512andWinternitzOTS_3withSPR extends
			CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SWIFFTX512andWinternitzOTS_3withSPR.OID;

		/**
		 * Constructor.
		 */
		public SWIFFTX512andWinternitzOTS_3withSPR() {
			super("1.3.6.1.4.1.8301.3.1.3.2.415", new SWIFFTX512(),
					new WinternitzOTS(3), true);
		}
	}

	/**
	 * CMSSSignature with SWIFFTX512 message digest, Winternitz OTS with
	 * parameter w=4, SWIFFTX224PRNG and SPR
	 */
	public static class SWIFFTX512andWinternitzOTS_4withSPR extends
			CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SWIFFTX512andWinternitzOTS_4withSPR.OID;

		/**
		 * Constructor.
		 */
		public SWIFFTX512andWinternitzOTS_4withSPR() {
			super("1.3.6.1.4.1.8301.3.1.3.2.416", new SWIFFTX512(),
					new WinternitzOTS(4), true);
		}
	}

	// LM-OTS

	/**
	 * CMSS2Signature with SHA1 message digest, LM OTS, and SHA1PRNG
	 */
	public static class SHA1andLMOTS extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA1andLMOTS.OID;

		/**
		 * Constructor.
		 */
		public SHA1andLMOTS() {
			super("1.3.6.1.4.1.8301.3.1.3.2.117", new SHA1(), new LMOTS(),
					false);
		}
	}

	/**
	 * CMSS2Signature with SHA256 message digest, LM OTS, and SHA1PRNG
	 */
	public static class SHA256andLMOTS extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA256andLMOTS.OID;

		/**
		 * Constructor.
		 */
		public SHA256andLMOTS() {
			super("1.3.6.1.4.1.8301.3.1.3.2.118", new SHA256(), new LMOTS(),
					false);
		}
	}

	/**
	 * CMSS2Signature with SHA384 message digest, LM OTS, and SHA1PRNG
	 */
	public static class SHA384andLMOTS extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA384andLMOTS.OID;

		/**
		 * Constructor.
		 */
		public SHA384andLMOTS() {
			super("1.3.6.1.4.1.8301.3.1.3.2.119", new SHA384(), new LMOTS(),
					false);
		}
	}

	/**
	 * CMSS2Signature with SHA512 message digest, LM OTS, and SHA1PRNG
	 */
	public static class SHA512andLMOTS extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA512andLMOTS.OID;

		/**
		 * Constructor.
		 */
		public SHA512andLMOTS() {
			super("1.3.6.1.4.1.8301.3.1.3.2.120", new SHA512(), new LMOTS(),
					false);
		}
	}

	/**
	 * CMSS2Signature with SWIFFTX224 message digest, LM OTS, and SWIFFTX224PRNG
	 */
	public static class SWIFFTX224andLMOTS extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SWIFFTX224andLMOTS.OID;

		/**
		 * Constructor.
		 */
		public SWIFFTX224andLMOTS() {
			super("1.3.6.1.4.1.8301.3.1.3.2.121", new SWIFFTX224(),
					new LMOTS(), false);
		}
	}

	/**
	 * CMSS2Signature with SWIFFTX256 message digest, LM OTS, and SWIFFTX256PRNG
	 */
	public static class SWIFFTX256andLMOTS extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SWIFFTX256andLMOTS.OID;

		/**
		 * Constructor.
		 */
		public SWIFFTX256andLMOTS() {
			super("1.3.6.1.4.1.8301.3.1.3.2.122", new SWIFFTX256(),
					new LMOTS(), false);
		}
	}

	/**
	 * CMSS2Signature with SWIFFTX384 message digest, LM OTS, and SWIFFTX384PRNG
	 */
	public static class SWIFFTX384andLMOTS extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SWIFFTX384andLMOTS.OID;

		/**
		 * Constructor.
		 */
		public SWIFFTX384andLMOTS() {
			super("1.3.6.1.4.1.8301.3.1.3.2.123", new SWIFFTX384(),
					new LMOTS(), false);
		}
	}

	/**
	 * CMSS2Signature with SWIFFTX512 message digest, LM OTS, and SWIFFTX512PRNG
	 */
	public static class SWIFFTX512andLMOTS extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SWIFFTX512andLMOTS.OID;

		/**
		 * Constructor.
		 */
		public SWIFFTX512andLMOTS() {
			super("1.3.6.1.4.1.8301.3.1.3.2.124", new SWIFFTX512(),
					new LMOTS(), false);
		}
	}

	/**
	 * CMSS2Signature with SHA1 message digest, Winternitz PRF OTS with
	 * parameter w=2, and SHA1PRNG
	 */
	public static class SHA1andWinternitzPRFOTS_2 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA1andWinternitzPRFOTS_2.OID;

		/**
		 * Constructor.
		 */
		public SHA1andWinternitzPRFOTS_2() {
			super("1.3.6.1.4.1.8301.3.1.3.2.40", new SHA1(),
					new WinternitzPRFOTS(2), false);
		}
	}

	/**
	 * CMSSSignature with SHA1 message digest, Winternitz PRF OTS with parameter
	 * w=3, and SHA1PRNG
	 */
	public static class SHA1andWinternitzPRFOTS_3 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA1andWinternitzPRFOTS_3.OID;

		/**
		 * Constructor.
		 */
		public SHA1andWinternitzPRFOTS_3() {
			super("1.3.6.1.4.1.8301.3.1.3.2.41", new SHA1(),
					new WinternitzPRFOTS(3), false);
		}
	}

	/**
	 * CMSSSignature with SHA1 message digest, Winternitz PRF OTS with parameter
	 * w=4, and SHA1PRNG
	 */
	public static class SHA1andWinternitzPRFOTS_4 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA1andWinternitzPRFOTS_4.OID;

		/**
		 * Constructor.
		 */
		public SHA1andWinternitzPRFOTS_4() {
			super("1.3.6.1.4.1.8301.3.1.3.2.42", new SHA1(),
					new WinternitzPRFOTS(4), false);
		}
	}

	/**
	 * CMSSSignature with SHA1 message digest, Winternitz PRF OTS with parameter
	 * w=5, and SHA1PRNG
	 */
	public static class SHA1andWinternitzPRFOTS_5 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA1andWinternitzPRFOTS_5.OID;

		/**
		 * Constructor.
		 */
		public SHA1andWinternitzPRFOTS_5() {
			super("1.3.6.1.4.1.8301.3.1.3.2.43", new SHA1(),
					new WinternitzPRFOTS(5), false);
		}
	}

	/**
	 * CMSSSignature with SHA1 message digest, Winternitz PRF OTS with parameter
	 * w=8, and SHA1PRNG
	 */
	public static class SHA1andWinternitzPRFOTS_8 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA1andWinternitzPRFOTS_8.OID;

		/**
		 * Constructor.
		 */
		public SHA1andWinternitzPRFOTS_8() {
			super("1.3.6.1.4.1.8301.3.1.3.2.44", new SHA1(),
					new WinternitzPRFOTS(8), false);
		}
	}

	/**
	 * CMSSSignature with SHA1 message digest, Winternitz PRF OTS with parameter
	 * w=16, and SHA1PRNG
	 */
	public static class SHA1andWinternitzPRFOTS_16 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA1andWinternitzPRFOTS_16.OID;

		/**
		 * Constructor.
		 */
		public SHA1andWinternitzPRFOTS_16() {
			super("1.3.6.1.4.1.8301.3.1.3.2.45", new SHA1(),
					new WinternitzPRFOTS(16), false);
		}
	}

	/**
	 * CMSSSignature with SHA1 message digest, Winternitz PRF OTS with parameter
	 * w=20, and SHA1PRNG
	 */
	public static class SHA1andWinternitzPRFOTS_20 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA1andWinternitzPRFOTS_16.OID;

		/**
		 * Constructor.
		 */
		public SHA1andWinternitzPRFOTS_20() {
			super("1.3.6.1.4.1.8301.3.1.3.2.45", new SHA1(),
					new WinternitzPRFOTS(20), false);
		}
	}

	/**
	 * CMSSSignature with SHA256 message digest, Winternitz PRF OTS with
	 * parameter w=2, and SHA1PRNG
	 */
	public static class SHA256andWinternitzPRFOTS_2 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA256andWinternitzPRFOTS_2.OID;

		/**
		 * Constructor.
		 */
		public SHA256andWinternitzPRFOTS_2() {
			super("1.3.6.1.4.1.8301.3.1.3.2.46", new SHA256(),
					new WinternitzPRFOTS(2), false);
		}
	}

	/**
	 * CMSSSignature with SHA256 message digest, Winternitz PRF OTS with
	 * parameter w=3, and SHA1PRNG
	 */
	public static class SHA256andWinternitzPRFOTS_3 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA256andWinternitzPRFOTS_3.OID;

		/**
		 * Constructor.
		 */
		public SHA256andWinternitzPRFOTS_3() {
			super("1.3.6.1.4.1.8301.3.1.3.2.47", new SHA256(),
					new WinternitzPRFOTS(3), false);
		}
	}

	/**
	 * CMSSSignature with SHA256 message digest, Winternitz PRF OTS with
	 * parameter w=4, and SHA1PRNG
	 */
	public static class SHA256andWinternitzPRFOTS_4 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA256andWinternitzPRFOTS_4.OID;

		/**
		 * Constructor.
		 */
		public SHA256andWinternitzPRFOTS_4() {
			super("1.3.6.1.4.1.8301.3.1.3.2.48", new SHA256(),
					new WinternitzPRFOTS(4), false);
		}
	}

	/**
	 * CMSSSignature with SHA256 message digest, Winternitz PRF OTS with
	 * parameter w=5, and SHA1PRNG
	 */
	public static class SHA256andWinternitzPRFOTS_5 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA256andWinternitzPRFOTS_5.OID;

		/**
		 * Constructor.
		 */
		public SHA256andWinternitzPRFOTS_5() {
			super("1.3.6.1.4.1.8301.3.1.3.2.49", new SHA256(),
					new WinternitzPRFOTS(5), false);
		}
	}

	/**
	 * CMSSSignature with SHA256 message digest, Winternitz PRF OTS with
	 * parameter w=8, and SHA1PRNG
	 */
	public static class SHA256andWinternitzPRFOTS_8 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA256andWinternitzPRFOTS_8.OID;

		/**
		 * Constructor.
		 */
		public SHA256andWinternitzPRFOTS_8() {
			super("1.3.6.1.4.1.8301.3.1.3.2.50", new SHA256(),
					new WinternitzPRFOTS(8), false);
		}
	}

	/**
	 * CMSSSignature with SHA256 message digest, Winternitz PRF OTS with
	 * parameter w=16, and SHA1PRNG
	 */
	public static class SHA256andWinternitzPRFOTS_16 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA256andWinternitzPRFOTS_16.OID;

		/**
		 * Constructor.
		 */
		public SHA256andWinternitzPRFOTS_16() {
			super("1.3.6.1.4.1.8301.3.1.3.2.51", new SHA256(),
					new WinternitzPRFOTS(16), false);
		}
	}

	/**
	 * CMSSSignature with SHA384 message digest, Winternitz PRF OTS with
	 * parameter w=2, and SHA1PRNG
	 */
	public static class SHA384andWinternitzPRFOTS_2 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA384andWinternitzPRFOTS_2.OID;

		/**
		 * Constructor.
		 */
		public SHA384andWinternitzPRFOTS_2() {
			super("1.3.6.1.4.1.8301.3.1.3.2.52", new SHA384(),
					new WinternitzPRFOTS(2), false);
		}
	}

	/**
	 * CMSSSignature with SHA384 message digest, Winternitz PRF OTS with
	 * parameter w=3, and SHA1PRNG
	 */
	public static class SHA384andWinternitzPRFOTS_3 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA384andWinternitzPRFOTS_3.OID;

		/**
		 * Constructor.
		 */
		public SHA384andWinternitzPRFOTS_3() {
			super("1.3.6.1.4.1.8301.3.1.3.2.53", new SHA384(),
					new WinternitzPRFOTS(3), false);
		}
	}

	/**
	 * CMSSSignature with SHA384 message digest, Winternitz PRF OTS with
	 * parameter w=4, and SHA1PRNG
	 */
	public static class SHA384andWinternitzPRFOTS_4 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA384andWinternitzPRFOTS_4.OID;

		/**
		 * Constructor.
		 */
		public SHA384andWinternitzPRFOTS_4() {
			super("1.3.6.1.4.1.8301.3.1.3.2.54", new SHA384(),
					new WinternitzPRFOTS(4), false);
		}
	}

	/**
	 * CMSSSignature with SHA384 message digest, Winternitz PRF OTS with
	 * parameter w=5, and SHA1PRNG
	 */
	public static class SHA384andWinternitzPRFOTS_5 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA384andWinternitzPRFOTS_5.OID;

		/**
		 * Constructor.
		 */
		public SHA384andWinternitzPRFOTS_5() {
			super("1.3.6.1.4.1.8301.3.1.3.2.55", new SHA384(),
					new WinternitzPRFOTS(5), false);
		}
	}

	/**
	 * CMSSSignature with SHA384 message digest, Winternitz PRF OTS with
	 * parameter w=8, and SHA1PRNG
	 */
	public static class SHA384andWinternitzPRFOTS_8 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA384andWinternitzPRFOTS_8.OID;

		/**
		 * Constructor.
		 */
		public SHA384andWinternitzPRFOTS_8() {
			super("1.3.6.1.4.1.8301.3.1.3.2.56", new SHA384(),
					new WinternitzPRFOTS(8), false);
		}
	}

	/**
	 * CMSSSignature with SHA384 message digest, Winternitz PRF OTS with
	 * parameter w=16, and SHA1PRNG
	 */
	public static class SHA384andWinternitzPRFOTS_16 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA384andWinternitzPRFOTS_16.OID;

		/**
		 * Constructor.
		 */
		public SHA384andWinternitzPRFOTS_16() {
			super("1.3.6.1.4.1.8301.3.1.3.2.57", new SHA384(),
					new WinternitzPRFOTS(16), false);
		}
	}

	/**
	 * CMSSSignature with SHA512 message digest, Winternitz PRF OTS with
	 * parameter w=2, and SHA1PRNG
	 */
	public static class SHA512andWinternitzPRFOTS_2 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA512andWinternitzPRFOTS_2.OID;

		/**
		 * Constructor.
		 */
		public SHA512andWinternitzPRFOTS_2() {
			super("1.3.6.1.4.1.8301.3.1.3.2.58", new SHA512(),
					new WinternitzPRFOTS(2), false);
		}
	}

	/**
	 * CMSSSignature with SHA512 message digest, Winternitz PRF OTS with
	 * parameter w=3, and SHA1PRNG
	 */
	public static class SHA512andWinternitzPRFOTS_3 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA512andWinternitzPRFOTS_3.OID;

		/**
		 * Constructor.
		 */
		public SHA512andWinternitzPRFOTS_3() {
			super("1.3.6.1.4.1.8301.3.1.3.2.59", new SHA512(),
					new WinternitzPRFOTS(3), false);
		}
	}

	/**
	 * CMSSSignature with SHA512 message digest, Winternitz PRF OTS with
	 * parameter w=4, and SHA1PRNG
	 */
	public static class SHA512andWinternitzPRFOTS_4 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA512andWinternitzPRFOTS_4.OID;

		/**
		 * Constructor.
		 */
		public SHA512andWinternitzPRFOTS_4() {
			super("1.3.6.1.4.1.8301.3.1.3.2.60", new SHA512(),
					new WinternitzPRFOTS(4), false);
		}
	}

	/**
	 * CMSSSignature with SHA512 message digest, Winternitz PRF OTS with
	 * parameter w=5, and SHA1PRNG
	 */
	public static class SHA512andWinternitzPRFOTS_5 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA512andWinternitzPRFOTS_5.OID;

		/**
		 * Constructor.
		 */
		public SHA512andWinternitzPRFOTS_5() {
			super("1.3.6.1.4.1.8301.3.1.3.2.61", new SHA512(),
					new WinternitzPRFOTS(5), false);
		}
	}

	/**
	 * CMSSSignature with SHA512 message digest, Winternitz PRF OTS with
	 * parameter w=8, and SHA1PRNG
	 */
	public static class SHA512andWinternitzPRFOTS_8 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA512andWinternitzPRFOTS_8.OID;

		/**
		 * Constructor.
		 */
		public SHA512andWinternitzPRFOTS_8() {
			super("1.3.6.1.4.1.8301.3.1.3.2.62", new SHA512(),
					new WinternitzPRFOTS(8), false);
		}
	}

	/**
	 * CMSSSignature with SHA512 message digest, Winternitz PRF OTS with
	 * parameter w=16, and SHA1PRNG
	 */
	public static class SHA512andWinternitzPRFOTS_16 extends CMSSSignature {

		/**
		 * The OID of the algorithm
		 */
		public static final String OID = CMSSKeyPairGenerator.SHA512andWinternitzPRFOTS_16.OID;

		/**
		 * Constructor.
		 */
		public SHA512andWinternitzPRFOTS_16() {
			super("1.3.6.1.4.1.8301.3.1.3.2.63", new SHA512(),
					new WinternitzPRFOTS(16), false);
		}
	}

	// //////////////////////////////////////////////////////////////////////////////

	/**
	 * Constructor.
	 * 
	 * @param oidString
	 *            the OID string identifying the algorithm
	 * @param md
	 *            the message digest used to build the authentication trees and
	 *            for the OTS
	 * @param ots
	 *            the underlying OTS
	 * @param useSpr
	 *            use SPR-CMSS (true) or not (false)
	 */
	protected CMSSSignature(String oidString, MessageDigest md, OTS ots,
			boolean useSpr) {
		oid = oidString;
		this.md = md;
		mdLength = md.getDigestLength();
		rng = new FIPS_186_2_PRNG();
		rng.initialize(md);
		ots.init(md, rng);
		this.ots = ots;
		this.useSpr = useSpr;
	}

	/**
	 * Initialize the signature algorithm for signing a message.
	 * 
	 * @param key
	 *            the private key of the signer
	 * @param random
	 *            a source of randomness (not used)
	 * @throws InvalidKeyException
	 *             if the key is not an instance of OTSPrivateKey.
	 */
	public void initSign(PrivateKey key, SecureRandom random)
			throws InvalidKeyException {

		// reset the signature object
		reset();

		if (!(key instanceof CMSSPrivateKey)) {
			throw new InvalidKeyException("unsupported type");
		}
		privKey = (CMSSPrivateKey) key;

		// check if OID stored in the key matches algorithm OID
		if (!privKey.getOIDString().equals(oid)) {
			throw new InvalidKeyException("invalid key for this signature");
		}

		md.reset();
		baos = new ByteArrayOutputStream();

		// obtain required parameters from private key

		heightOfTrees = privKey.getHeightOfTrees();
		numLeafs = privKey.getNumLeafs();

		indexMain = privKey.getIndexMain();
		indexSub = privKey.getIndexSub();
		seeds = privKey.getSeeds();
		authPath = privKey.getAuthPath();
		activeSubtree = privKey.getActiveSubtree();
		subtreeRootSig = privKey.getSubtreeRootSig();
		maintreeOTSVerificationKey = privKey.getMaintreeOTSVerificationKey();

		if (useSpr) {
			if (privKey.getMasks() == null) {
				throw new IllegalArgumentException(
						"Masks must not be null if SPR is in use.");
			}
			byte[][][] masks = privKey.getMasks();
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

		int K = 2;
		if (heightOfTrees % 2 != 0)
			K += 1;
		authPath[0].setup(md, ots, rng, mainNc);
		authPath[1].setup(md, ots, rng, subNc);
		authPath[2].setup(md, ots, rng, subNc);

	}

	/**
	 * Initialize the signature algorithm for verifying a signature.
	 * 
	 * @param key
	 *            the public key of the signer.
	 * @throws InvalidKeyException
	 *             if the public key is not an instance of CMSS2PublicKey.
	 */
	public void initVerify(PublicKey key) throws InvalidKeyException {

		// reset the signature object
		reset();

		if (!(key instanceof CMSSPublicKey)) {
			throw new InvalidKeyException("unsupported type");
		}
		pubKey = (CMSSPublicKey) key;

		// check if OID stored in the key matches algorithm OID
		if (!pubKey.getOIDString().equals(oid)) {
			throw new InvalidKeyException("invalid key for this signature");
		}

		pubKeyBytes = pubKey.getKeyBytes();

		md.reset();
		baos = new ByteArrayOutputStream();

		if (pubKey.getMasks() != null) {
			byte[][][] masks = pubKey.getMasks();
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
	}

	/**
	 * Initialize this signature engine with the specified parameter set (not
	 * used).
	 * 
	 * @param params
	 *            the parameters (not used)
	 */
	public void setParameters(AlgorithmParameterSpec params) {
		// parameters are not used
	}

	/**
	 * Feed a message byte to the message digest.
	 * 
	 * @param data
	 *            array of message bytes
	 */
	public void update(byte data) {
		baos.write(data);
	}

	/**
	 * Feed message bytes to the message digest.
	 * 
	 * @param data
	 *            array of message bytes
	 * @param offset
	 *            index of message start
	 * @param length
	 *            number of message bytes
	 */
	public void update(byte[] data, int offset, int length) {
		baos.write(data, offset, length);
	}

	/**
	 * Sign a message.
	 * 
	 * @return the signature.
	 * @throws SignatureException
	 *             if no more signatures can be generated with the private key.
	 */
	public byte[] sign() throws SignatureException {

		// check if last signature has been generated
		if (indexMain >= numLeafs) {
			throw new SignatureException(
					"No more signatures can be generated with this key.");
		}
		/* first part of the signature */

		// obtain the message
		byte[] message = getData();

		// generate the new subtree seed and one-time signature of the message
		byte[] otsSeed = rng.nextSeed(seeds[1]);
		ots.generateSignatureKey(otsSeed);
		byte[] otsSig = ots.sign(message);

		// if the current subtree node is a left node, store it for the next
		// authentication path
		if (!ots.canComputeVerificationKeyFromSignature()) {
			ots.generateVerificationKey();
		}

		if ((indexSub & 1) == 0) {
			if (!ots.canComputeVerificationKeyFromSignature()) {
				authPath[1 + activeSubtree].setLeftLeaf(subNc.getLeaf(ots
						.getVerificationKey()));
			} else {
				authPath[1 + activeSubtree].setLeftLeaf(subNc.getLeaf(ots
						.computeVerificationKey(message, otsSig)));
			}
		}

		/* subtree part of signature */
		// convert subtree index into a byte array
		byte[] indexBytes = LittleEndianConversions.I2OSP(indexSub);

		// get concatenated subtree authentication path
		byte[] authPathBytes = ByteUtils
				.concatenate(authPath[1 + activeSubtree].getAuthPath());

		// concatenate index, otsSig, maybe OTSPubKey and authPathBytes
		byte[] firstHalf = ByteUtils.concatenate(indexBytes, otsSig);
		if (!ots.canComputeVerificationKeyFromSignature())
			firstHalf = ByteUtils.concatenate(firstHalf, ots
					.getVerificationKey());
		firstHalf = ByteUtils.concatenate(firstHalf, authPathBytes);

		/* maintree part of signature */
		// convert main tree index into a byte array
		indexBytes = LittleEndianConversions.I2OSP(indexMain);

		// get concatenated main tree authentication path
		authPathBytes = ByteUtils.concatenate(authPath[0].getAuthPath());

		// concatenate index, subtreeRootSig, and authPathBytes
		byte[] secondHalf = ByteUtils.concatenate(indexBytes, subtreeRootSig);
		if (!ots.canComputeVerificationKeyFromSignature())
			secondHalf = ByteUtils.concatenate(secondHalf,
					maintreeOTSVerificationKey);
		secondHalf = ByteUtils.concatenate(secondHalf, authPathBytes);

		// change private key for next signature and reset signature
		if (indexSub < numLeafs - 1 || indexMain < numLeafs - 1) {
			nextKey();
			privKey.update(indexMain, indexSub, seeds, authPath, activeSubtree,
					subtreeRootSig, maintreeOTSVerificationKey);
		} else
			privKey.update(numLeafs, numLeafs, null, null, 0, null, null);

		// concatenate the two halves of the CMSS2 signature and return
		return ByteUtils.concatenate(firstHalf, secondHalf);
	}

	/**
	 * Verify a signature.
	 * 
	 * @param sigBytes
	 *            the signature to be verified.
	 * @return <tt>true</tt> if the signature is correct, <tt>flase</tt>
	 *         otherwise
	 */
	public boolean verify(byte[] sigBytes) {
		int otsSigLength = ots.getSignatureLength();
		int otsPubKeyLength = ots.getVerificationKeyLength();

		if (ots.canComputeVerificationKeyFromSignature())
			heightOfTrees = (sigBytes.length / 2 - otsSigLength - 4) / mdLength;
		else
			heightOfTrees = (sigBytes.length / 2 - otsSigLength
					- otsPubKeyLength - 4)
					/ mdLength;

		/* first part */

		// obtain the message
		byte[] message = getData();

		// get the subtree index
		int index = LittleEndianConversions.OS2IP(sigBytes, 0);

		// 4 is the number of bytes in integer
		int nextEntry = 4;

		// get one-time signature of the message
		byte[] otsSig = new byte[otsSigLength];
		System.arraycopy(sigBytes, nextEntry, otsSig, 0, otsSigLength);
		nextEntry += otsSigLength;

		// get one-time verification key from signature
		byte[] otsPubKey;
		if (ots.canComputeVerificationKeyFromSignature()) {
			// if one-time verification key can be computed from signature and
			// message, e.g. Winternitz
			otsPubKey = ots.computeVerificationKey(message, otsSig);
			if (otsPubKey == null)
				return false;
		} else {
			// else, e.g. LM-OTS
			otsPubKey = new byte[otsPubKeyLength];
			// System.out.println(otsSig.length);
			System
					.arraycopy(sigBytes, nextEntry, otsPubKey, 0,
							otsPubKeyLength);
			nextEntry += otsPubKeyLength;
			if (!ots.verify(message, otsSig, otsPubKey))
				return false;
		}

		// get authentication path from the signature
		byte[][] authPath = new byte[heightOfTrees][mdLength];
		for (int i = 0; i < heightOfTrees; i++, nextEntry += mdLength) {
			System.arraycopy(sigBytes, nextEntry, authPath[i], 0, mdLength);
		}

		// compute the subtree root from the authentication path
		byte[] help = subNc.getLeaf(otsPubKey);
		for (int i = 0; i < heightOfTrees; i++, index /= 2) {
			if ((index & 1) == 0) {
				help = subNc.computeParent(help, authPath[i], i);
			} else {
				help = subNc.computeParent(authPath[i], help, i);
			}
		}

		// now help contains the root of the subtree
		byte[] subtreeRoot = help;

		/* second part */

		// get the main tree index
		index = LittleEndianConversions.OS2IP(sigBytes, nextEntry);
		nextEntry += 4;

		// get one-time signature
		otsSig = new byte[otsSigLength];
		System.arraycopy(sigBytes, nextEntry, otsSig, 0, otsSigLength);
		nextEntry += otsSigLength;

		// get one-time verification key from signature
		if (ots.canComputeVerificationKeyFromSignature()) {
			// if one-time verification key can be computed from signature and
			// message, e.g. Winternitz
			otsPubKey = ots.computeVerificationKey(subtreeRoot, otsSig);
			if (otsPubKey == null)
				return false;
		} else {
			// else, e.g. LM-OTS
			otsPubKey = new byte[otsPubKeyLength];
			System
					.arraycopy(sigBytes, nextEntry, otsPubKey, 0,
							otsPubKeyLength);
			nextEntry += otsPubKeyLength;
			if (!ots.verify(subtreeRoot, otsSig, otsPubKey))
				return false;
		}

		// get authentication path from the signature
		for (int i = 0; i < heightOfTrees; i++, nextEntry += mdLength) {
			System.arraycopy(sigBytes, nextEntry, authPath[i], 0, mdLength);
		}

		// compute the main tree root from the authentication path
		help = mainNc.getLeaf(otsPubKey);
		for (int i = 0; i < heightOfTrees; i++, index /= 2) {
			if ((index & 1) == 0) {
				help = mainNc.computeParent(help, authPath[i], i);
			} else {
				help = mainNc.computeParent(authPath[i], help, i);
			}
		}

		// now help contains the main tree root
		byte[] maintreeRoot = help;

		// check whether the computed main tree root is equal to the
		// public key
		return ByteUtils.equals(maintreeRoot, pubKeyBytes);
	}

	/**
	 * @return the data contained in the ByteArrayOutputStream. Closes the
	 *         stream.
	 */
	private byte[] getData() {
		byte[] data = baos.toByteArray();

		try {
			baos.close();
		} catch (IOException ioe) {
			System.err.println("Can not close ByteArrayOutputStream");
		}
		baos.reset();
		return data;
	}

	/**
	 * This method updates the CMSS2 private key for the next signature
	 */
	private void nextKey() {
		if (indexSub == numLeafs - 1) {
			/* switch to next subtree */
			nextTree();
		} else {
			/* process current subtree */

			authPath[1 + activeSubtree].update(indexSub);
			/* process next subtree, if there is one */
			if (indexMain < numLeafs - 1) {
				authPath[2 - activeSubtree].initializationUpdate(indexSub,
						seeds[2]);

			}

			/* update indexSub */
			indexSub++;
		}
	}

	/**
	 * Switch to next subtree if the current one is depleted
	 */
	private void nextTree() {
		/* process next subtree and get root of next subtree */

		/* update auth path of main tree and indexMain */
		authPath[0].update(indexMain);
		indexMain++;

		/* complete construction of next subtree */
		authPath[2 - activeSubtree].initializationUpdate(indexSub, seeds[2]);
		byte[] subtreeRoot = authPath[2 - activeSubtree]
				.initializationFinalize();

		/* sign root of next subtree */
		byte[] otsSeed = rng.nextSeed(seeds[0]);
		ots.generateSignatureKey(otsSeed);
		subtreeRootSig = ots.sign(subtreeRoot);

		if (!ots.canComputeVerificationKeyFromSignature()) {
			ots.generateVerificationKey();
			maintreeOTSVerificationKey = ots.getVerificationKey();
		}

		// if the current subtree node is a left node, store it for the next
		// authentication path
		if ((indexMain & 1) == 0) {
			if (!ots.canComputeVerificationKeyFromSignature()) {
				authPath[0].setLeftLeaf(mainNc
						.getLeaf(maintreeOTSVerificationKey));
			} else {
				authPath[0].setLeftLeaf(mainNc.getLeaf(ots
						.computeVerificationKey(subtreeRoot, subtreeRootSig)));
			}
		}

		/* update indexSub */
		indexSub = 0;

		/* copy authentication path from next tree to current tree */
		rng.nextSeed(seeds[1]);
		// authPath[1].copy(authPath[2]);

		/* initialize authentication path computation for next subtree */
		rng.nextSeed(seeds[2]);
		authPath[1 + activeSubtree].initializationSetup();

		activeSubtree = 1 - activeSubtree;

	}

	/**
	 * Reset the internal state of the signature.
	 */
	private void reset() {
		privKey = null;
		pubKey = null;
		pubKeyBytes = null;
		baos = null;
		indexMain = 0;
		indexSub = 0;
		seeds = null;
		authPath = null;
		subtreeRootSig = null;
		heightOfTrees = 0;
		numLeafs = 0;
	}

}
