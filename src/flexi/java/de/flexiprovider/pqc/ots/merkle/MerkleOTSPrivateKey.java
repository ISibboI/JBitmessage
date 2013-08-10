package de.flexiprovider.pqc.ots.merkle;

import codec.asn1.ASN1Null;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1OctetString;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1SequenceOf;
import codec.asn1.ASN1Type;
import de.flexiprovider.api.keys.PrivateKey;
import de.flexiprovider.common.util.ASN1Tools;
import de.flexiprovider.common.util.ByteUtils;

/**
 * This class implements the MerkleOTS private key.
 * 
 * @author Elena Klintsevich
 * @see MerkleOTSKeyPairGenerator
 */
public class MerkleOTSPrivateKey extends PrivateKey {

    // the OID of the algorithm
    private String oid;

    // the key bytes
    private byte[][] keyBytes;

    /**
     * Construct a new MerkleOTS private key.
     * 
     * @param oid
     *                the OID of the algorithm
     * @param keyBytes
     *                the key bytes
     */
    protected MerkleOTSPrivateKey(String oid, byte[][] keyBytes) {
	this.oid = oid;
	this.keyBytes = keyBytes;
    }

    /**
     * Construct a new MerkleOTS private key from the given key specification.
     * 
     * @param keySpec
     *                a {@link MerkleOTSPrivateKeySpec}
     */
    protected MerkleOTSPrivateKey(MerkleOTSPrivateKeySpec keySpec) {
	this(keySpec.getOIDString(), keySpec.getKeyBytes());
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
    protected byte[][] getKeyBytes() {
	return keyBytes;
    }

    public boolean equals(Object other) {
	if (other == null || !(other instanceof MerkleOTSPrivateKey)) {
	    return false;
	}

	MerkleOTSPrivateKey otherKey = (MerkleOTSPrivateKey) other;

	boolean result = oid.equals(otherKey.oid);
	for (int i = 0; i < keyBytes.length; i++) {
	    result &= ByteUtils.equals(keyBytes[i], otherKey.keyBytes[i]);
	}

	return result;
    }

    public int hashCode() {
	return oid.hashCode() + keyBytes.hashCode();
    }

    public String toString() {
	String result = "Merkle OTS private key:\n";
	result += " OID      : " + oid + "\n";
	result += " key bytes:\n";
	for (int i = 0; i < keyBytes.length; i++) {
	    result += "  " + i + ": " + ByteUtils.toHexString(keyBytes[i])
		    + "\n";
	}
	return result;
    }

    /**
     * @return the OID to encode in the SubjectPublicKeyInfo structure
     */
    protected ASN1ObjectIdentifier getOID() {
	return new ASN1ObjectIdentifier(MerkleOTSKeyFactory.OID);
    }

    /**
     * @return the algorithm parameters to encode in the SubjectPublicKeyInfo
     *         structure
     */
    protected ASN1Type getAlgParams() {
	return new ASN1Null();
    }

    /**
     * @return the keyData to encode in the SubjectPublicKeyInfo structure
     */
    protected byte[] getKeyData() {
	ASN1Sequence keyData = new ASN1Sequence();

	// encode OID string
	keyData.add(new ASN1ObjectIdentifier(oid));

	// encode private key bytes
	ASN1SequenceOf keySequence = new ASN1SequenceOf(ASN1OctetString.class);
	for (int i = 0; i < keyBytes.length; i++) {
	    keySequence.add(new ASN1OctetString(keyBytes[i]));
	}
	keyData.add(keySequence);

	return ASN1Tools.derEncode(keyData);
    }

}
