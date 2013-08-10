package de.flexiprovider.pqc.hbc.cmss;

import codec.asn1.ASN1Integer;
import codec.asn1.ASN1Null;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1OctetString;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1SequenceOf;
import codec.asn1.ASN1Type;
import de.flexiprovider.api.keys.PrivateKey;
import de.flexiprovider.common.util.ASN1Tools;
import de.flexiprovider.common.util.ByteUtils;
import de.flexiprovider.pqc.hbc.cmss.CMSSKeyPairGenerator;
import de.flexiprovider.pqc.hbc.cmss.CMSSPrivateKeySpec;

/**
 * This class implements a CMSS private key and is usually initiated by the
 * {@link CMSSKeyPairGenerator}.
 * 
 * @author Elena Klintsevich
 * @author Martin D�ring
 * @see CMSSKeyPairGenerator
 * @see CMSSPrivateKeySpec
 */
public class CMSSPrivateKey extends PrivateKey {

	// the OID of the algorithm
	private String oid;

	// the main tree index
	private int indexMain;

	// the subtree index
	private int indexSub;

	// the height of the authentication trees
	private int heightOfTrees;

	// the number of leafs of each tree
	private int numLeafs;

	// array of 3 seeds for the main tree, current subtree and next subtree
	private byte[][] seeds = new byte[3][];

	// the size of the seed used for key pair generation
	private int seedSize;

	// array of 3 authentication paths for the main tree, current subtree and
	// next subtree
	private BDSAuthPath[] authPath;
	private int activeSubtree;

	// the one-time signature of the root of the current subtree
	private byte[] subtreeRootSig;

	// the one-time verification key used to verify the rootSignature of the
	// subtree
	private byte[] maintreeOTSVerificationKey;

	// the masks for spr-cmss
	private byte[][][] masks;

	/**
	 * Construct a new CMSS2 private key.
	 * 
	 * @param oid
	 *            the OID of the algorithm
	 * @param indexMain
	 *            main tree index
	 * @param indexSub
	 *            subtree index
	 * @param heightOfTrees
	 *            height of trees
	 * @param seeds
	 *            array of seeds for the key generation
	 * @param authPath
	 *            array of authentication paths
	 * @param subtreeRootSig
	 *            the one-time signature of the root of the current subtree
	 * @param maintreeOTSPubKey
	 *            the one-time public key used to verify the rootSignature of
	 *            the subtree
	 */
	protected CMSSPrivateKey(String oid, int indexMain, int indexSub,
			int heightOfTrees, byte[][] seeds, BDSAuthPath[] authPath,
			int activeSubtree, byte[] subtreeRootSig,
			byte[] maintreeOTSVerificationKey, byte[][][] masks) {
		this.oid = oid;
		this.indexMain = indexMain;
		this.indexSub = indexSub;

		this.heightOfTrees = heightOfTrees;
		numLeafs = 1 << heightOfTrees;

		this.seeds = seeds;
		seedSize = seeds[0].length;

		this.authPath = authPath;
		this.activeSubtree = activeSubtree;

		this.subtreeRootSig = subtreeRootSig;
		this.maintreeOTSVerificationKey = maintreeOTSVerificationKey;

		this.masks = masks;
	}

	/**
	 * Construct a new CMSS2 private key from the given key specification.
	 * 
	 * @param keySpec
	 *            a {@link CMSS2PrivateKeySpec}
	 */
	protected CMSSPrivateKey(CMSSPrivateKeySpec keySpec) {
		this(keySpec.getOIDString(), keySpec.getIndexMain(), keySpec
				.getIndexSub(), keySpec.getHeightOfTrees(), keySpec.getSeeds(),
				keySpec.getAuthPaths(), keySpec.getActiveSubtree(), keySpec
						.getSubtreeRootSig(), keySpec
						.getMaintreeOTSVerificationKey(), keySpec.getMasks());
	}

	/**
	 * Update the private key components.
	 * 
	 * @param indexMain
	 *            main tree index
	 * @param indexSub
	 *            subtree index
	 * @param seeds
	 *            array of seeds for the key generation
	 * @param authPaths
	 *            array of authentication paths
	 * @param subtreeRootSig
	 *            the one-time signature of the root of the current subtree
	 * @param maintreeOTSPubKey
	 *            the one-time public key used to verify the rootSignature of
	 *            the subtree
	 * 
	 */
	protected void update(int indexMain, int indexSub, byte[][] seeds,
			BDSAuthPath[] authPath, int activeSubtree, byte[] subtreeRootSig,
			byte[] maintreeOTSVerificationKey) {
		this.indexMain = indexMain;
		this.indexSub = indexSub;
		this.seeds = seeds;
		this.authPath = authPath;
		this.activeSubtree = activeSubtree;
		this.subtreeRootSig = subtreeRootSig;
		this.maintreeOTSVerificationKey = maintreeOTSVerificationKey;
	}

	/**
	 * @return the OID of the algorithm
	 */
	public String getAlgorithm() {
		return oid;
	}

	/**
	 * @return the OID of the algorithm
	 */
	protected String getOIDString() {
		return oid;
	}

	/**
	 * @return the height of the authentication trees
	 */
	protected int getHeightOfTrees() {
		return heightOfTrees;
	}

	/**
	 * @return the number of leafs of each tree
	 */
	protected int getNumLeafs() {
		return numLeafs;
	}

	/**
	 * @return the size of the seed used for key pair generation
	 */
	protected int getSeedSize() {
		return seedSize;
	}

	/**
	 * @return the main tree index
	 */
	protected int getIndexMain() {
		return indexMain;
	}

	/**
	 * @return the subtree index
	 */
	protected int getIndexSub() {
		return indexSub;
	}

	/**
	 * @return the seeds
	 */
	protected byte[][] getSeeds() {
		return seeds;
	}

	/**
	 * @return the authentication paths
	 */
	protected BDSAuthPath[] getAuthPath() {
		return authPath;
	}

	/**
	 * @return the active Subtree
	 */
	protected int getActiveSubtree() {
		return activeSubtree;
	}

	/**
	 * @return the one-time signature of the root of the current subtree
	 */
	protected byte[] getSubtreeRootSig() {
		return subtreeRootSig;
	}

	/**
	 * @return the one-time public key used to verify the rootSignature of the
	 *         subtree
	 */
	protected byte[] getMaintreeOTSVerificationKey() {
		return maintreeOTSVerificationKey;
	}

	protected byte[][][] getMasks() {
		return masks;
	}

	/**
	 * @return a human readable form of the key
	 */
	public String toString() {
		String result = "CMSS2PrivateKey\n--------------\n\n";

		result += "main tree index            : " + indexMain + "\n";
		result += "subtree index              : " + indexSub + "\n";
		result += "height of trees            : " + heightOfTrees + "\n";

		result += "seeds:\n";
		if (seeds != null) {
			result += " main tree                 : "
					+ ByteUtils.toHexString(seeds[0]) + "\n";
			result += " current subtree           : "
					+ ByteUtils.toHexString(seeds[1]) + "\n";
			result += " next subtree              : "
					+ ByteUtils.toHexString(seeds[2]) + "\n";
		} else {
			result += " main tree                 : null \n";
			result += " current subtree           : null \n";
			result += " next subtree              : null \n";
		}

		result += "authentication paths:\n";
		if (authPath != null) {
			result += " main tree: \n";
			result += authPath[0].toString() + "\n";
			result += " current subtree: \n";
			result += authPath[1 + activeSubtree].toString() + "\n";
			result += " next subtree: \n";
			result += authPath[2 - activeSubtree].toString() + "\n";
		} else {
			result += " main tree: \n";
			result += " null \n";
			result += " current subtree: \n";
			result += " null \n";
			result += " next subtree: \n";
			result += " null \n";
		}

		if (subtreeRootSig != null) {
			result += "current subtreeRootSig     : "
					+ ByteUtils.toHexString(subtreeRootSig) + "\n";
		} else {
			result += "current subtreeRootSig     : null \n";
		}

		if (subtreeRootSig == null)
			result += "current subtree root sig  : null \n";
		else
			result += "current subtree root sig  : "
					+ ByteUtils.toHexString(subtreeRootSig) + "\n";

		if (maintreeOTSVerificationKey == null)
			result += "current maintreeOTSPubKey  : null \n";
		else
			result += "current maintreeOTSPubKey  : "
					+ ByteUtils.toHexString(maintreeOTSVerificationKey) + "\n";

		if (masks == null) {
			result += "PR Key: No";
		} else {
			result += "SPR Key: Yes";
		}

		return result;
	}

	/**
	 * Compare this CMSS2 private key with another object.
	 * 
	 * @param other
	 *            the other object
	 * @return the result of the comparison
	 */
	public boolean equals(Object other) {
		if (other == null || !(other instanceof CMSSPrivateKey)) {
			return false;
		}
		CMSSPrivateKey otherKey = (CMSSPrivateKey) other;

		boolean result = oid.equals(otherKey.oid);
		result &= indexMain == otherKey.indexMain;
		result &= indexSub == otherKey.indexSub;
		result &= ByteUtils.equals(seeds, otherKey.seeds);
		result &= authPath[0].equals(otherKey.authPath[0]);
		result &= authPath[1].equals(otherKey.authPath[1]);
		result &= authPath[2].equals(otherKey.authPath[2]);
		result &= activeSubtree == otherKey.activeSubtree;
		result &= ByteUtils.equals(subtreeRootSig, otherKey.subtreeRootSig);
		result &= ByteUtils.equals(maintreeOTSVerificationKey,
				otherKey.maintreeOTSVerificationKey);

		if (masks == null) {
			if (otherKey.getMasks() != null) {
				return false;
			}
			return result;
		}
		if (otherKey.getMasks() != null) {
			result &= ByteUtils.equals(masks, otherKey.getMasks());
		}

		return result;
	}

	public int hashCode() {
		int value = maintreeOTSVerificationKey == null ? 0
				: maintreeOTSVerificationKey.hashCode();
		value += masks == null ? 0 : masks.hashCode();

		return oid.hashCode() + indexMain + indexSub + seeds.hashCode()
				+ authPath[0].hashCode() + authPath[1].hashCode()
				+ authPath[2].hashCode() + activeSubtree
				+ subtreeRootSig.hashCode() + value;

	}

	/**
	 * @return the OID to encode in the SubjectPublicKeyInfo structure
	 */
	protected ASN1ObjectIdentifier getOID() {
		return new ASN1ObjectIdentifier(CMSSKeyFactory.OID);
	}

	/**
	 * @return the algorithm parameters to encode in the SubjectPublicKeyInfo
	 *         structure
	 */
	protected ASN1Type getAlgParams() {
		return new ASN1Null();
	}

	/**
	 * Return the key data to encode in the SubjectPublicKeyInfo structure.
	 * <p>
	 * The ASN.1 definition of the key structure is
	 * 
	 * <pre>
	 *    CMSS2PrivateKey ::= SEQUENCE {
	 *      oid                           OBJECT IDENTIFIER  -- OID identifying the algorithm
	 *      indexMain                     INTEGER            -- main tree index
	 *      indexSub                      INTEGER            -- subtree index
	 *      heightOfTrees                 INTEGER            -- height of trees
	 *      seeds[0]                      BIT STRING         -- seed for the main tree
	 *      seeds[1]                      BIT STRING         -- seed for the subtree
	 *      seeds[2]                      BIT STRING         -- seed for the next subtree
	 *      authPaths[0]                  AUTHPATH           -- authentication path of main tree
	 *      authPaths[1]                  AUTHPATH           -- authentication path of subtree
	 *      authPaths[2]                  AUTHPATH           -- authentication path of next subtree
	 *      activeSubtree                 INTEGER            -- active subtree
	 *      subtreeRootSig                OCTET STRING       -- the one-time signature of the root of the current subtree
	 *      maintreeOTSVerificationKey    OCTET STRING       -- the current verification key used in the maintree
	 *      leftMasks	   		  SECUENCE OF OCTET STRING		      
	 *     						     -- the left masks for spr-cmss
	 *      rightMasks	   		  SECUENCE OF OCTET STRING		      
	 *      						     -- the right masks for spr-cmss
	 *    }
	 * </pre>
	 * 
	 * @return the keyData to encode in the SubjectPublicKeyInfo structure
	 */
	protected byte[] getKeyData() {
		ASN1Sequence keyData = new ASN1Sequence();

		// encode <oidString>
		keyData.add(new ASN1ObjectIdentifier(oid));

		// encode <indexMain>
		keyData.add(new ASN1Integer(indexMain));

		// encode <indexSub>
		keyData.add(new ASN1Integer(indexSub));

		// encode <heightOfTrees>
		keyData.add(new ASN1Integer(heightOfTrees));

		// encode <seeds>
		keyData.add(new ASN1OctetString(seeds[0]));
		keyData.add(new ASN1OctetString(seeds[1]));
		keyData.add(new ASN1OctetString(seeds[2]));

		// encode <authPaths>
		ASN1Sequence authPath0 = authPath[0].getASN1();
		keyData.add(authPath0);

		ASN1Sequence authPath1 = authPath[1].getASN1();
		keyData.add(authPath1);

		ASN1Sequence authPath2 = authPath[2].getASN1();
		keyData.add(authPath2);

		// encode <activeSubtree>
		keyData.add(new ASN1Integer(activeSubtree));

		// encode <subtreeRootSig>
		keyData.add(new ASN1OctetString(subtreeRootSig));

		// encode <maintreeOTSVerificationKey>
		keyData.add(new ASN1OctetString(maintreeOTSVerificationKey));

		// encode left masks
		ASN1SequenceOf leftMasks = new ASN1SequenceOf(ASN1OctetString.class);
		if (masks != null) {
			for (int i = 0; i < masks.length; i++) {
				leftMasks.add(new ASN1OctetString(masks[i][0]));
			}
		}
		keyData.add(leftMasks);

		// encode right masks
		ASN1SequenceOf rightMasks = new ASN1SequenceOf(ASN1OctetString.class);
		if (masks != null) {
			for (int i = 0; i < masks.length; i++) {
				rightMasks.add(new ASN1OctetString(masks[i][1]));
			}
		}
		keyData.add(rightMasks);

		return ASN1Tools.derEncode(keyData);
	}

}
