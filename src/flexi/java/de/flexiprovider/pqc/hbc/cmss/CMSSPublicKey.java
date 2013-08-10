package de.flexiprovider.pqc.hbc.cmss;

import codec.asn1.ASN1Null;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1OctetString;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1SequenceOf;
import codec.asn1.ASN1Type;
import de.flexiprovider.api.keys.PublicKey;
import de.flexiprovider.common.util.ASN1Tools;
import de.flexiprovider.common.util.ByteUtils;

/**
 * This class implements the CMSS public key and is usually initiated by the
 * {@link CMSSKeyPairGenerator}.
 * 
 * @author Elena Klintsevich
 * @see de.flexiprovider.pqc.hbc.cmss.CMSSKeyPairGenerator
 * @see de.flexiprovider.pqc.hbc.cmss.CMSSPublicKeySpec
 */
public class CMSSPublicKey extends PublicKey {

	// the OID of the algorithm
	private String oid;

	// the key bytes
	private byte[] keyBytes;

	// the masks for spr-cmss
	private byte[][][] masks;

	/**
	 * Construct a new CMSS2 public key.
	 * 
	 * @param oid
	 *            the OID of the algorithm
	 * @param keyBytes
	 *            the key bytes
	 */
	protected CMSSPublicKey(String oid, byte[] keyBytes, byte[][][] masks) {
		this.oid = oid;
		this.keyBytes = keyBytes;
		this.masks = masks;
	}

	/**
	 * Construct a new CMSS2 public key from the given key specification.
	 * 
	 * @param keySpec
	 *            a {@link CMSS2PublicKeySpec}
	 */
	protected CMSSPublicKey(CMSSPublicKeySpec keySpec) {
		this(keySpec.getOIDString(), keySpec.getPubKeyBytes(), keySpec
				.getMasks());
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
	 * @return the key bytes
	 */
	protected byte[] getKeyBytes() {
		return keyBytes;
	}

	protected byte[][][] getMasks() {
		return masks;
	}

	/**
	 * @return a human readable form of the CMSS2 public key
	 */
	public String toString() {
		String out = "CMSS2 public key : " + ByteUtils.toHexString(keyBytes)
				+ "\n";

		return out;
	}

	public boolean equals(Object obj) {
		if (obj == null || !(obj instanceof CMSSPublicKey)) {
			return false;
		}

		CMSSPublicKey oKey = (CMSSPublicKey) obj;

		boolean value = oKey.oid.equals(oid);

		if (keyBytes.length != oKey.keyBytes.length) {
			return false;
		}

		value &= ByteUtils.equals(oKey.keyBytes, keyBytes);

		if (masks == null) {
			if (oKey.getMasks() != null) {
				return false;
			}
			return value;

		}
		if (oKey.getMasks() != null) {
			value &= ByteUtils.equals(masks, oKey.getMasks());
		}

		return value;
	}

	public int hashCode() {
		int result = ByteUtils.deepHashCode(keyBytes);
		if (masks != null)
			result += ByteUtils.deepHashCode(masks);

		return result + oid.hashCode();
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
	 * Return the key data to encode in the SubjectPublicKeyInfo structure. *
	 * <p>
	 * The ASN.1 definition of the key structure is
	 * 
	 * <pre>
	 *    CMSS2PublicKey ::= SEQUENCE {
	 *      oid            OBJECT IDENTIFIER  -- OID identifying the algorithm
	 *      pubKeyBytes    OCTET STRING       -- the public key bytes
	 *      leftMasks	   SECUENCE OF OCTET STRING		      
	 *      				      -- the left masks for spr-cmss
	 *      rightMasks	   SECUENCE OF OCTET STRING		      
	 *      				      -- the right masks for spr-cmss
	 *    }
	 * 
	 * </pre>
	 * 
	 * @return the keyData to encode in the SubjectPublicKeyInfo structure
	 */
	protected byte[] getKeyData() {
		ASN1Sequence keyData = new ASN1Sequence();

		// encode OID string
		keyData.add(new ASN1ObjectIdentifier(oid));

		// encode public key bytes
		keyData.add(new ASN1OctetString(keyBytes));

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
