package de.flexiprovider.pqc.ots.merkle;

import codec.CorruptedCodeException;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1OctetString;
import codec.asn1.ASN1Sequence;
import codec.pkcs8.PrivateKeyInfo;
import codec.x509.SubjectPublicKeyInfo;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.exceptions.InvalidKeySpecException;
import de.flexiprovider.api.keys.Key;
import de.flexiprovider.api.keys.KeyFactory;
import de.flexiprovider.api.keys.KeySpec;
import de.flexiprovider.api.keys.PrivateKey;
import de.flexiprovider.api.keys.PublicKey;
import de.flexiprovider.common.util.ASN1Tools;
import de.flexiprovider.pki.PKCS8EncodedKeySpec;
import de.flexiprovider.pki.X509EncodedKeySpec;

/**
 * This class is able to transform MerkleOTS keys and MerkleOTS key
 * specifications into a form that can be used with the FlexiProvider.
 * 
 * @author Elena Klintsevich
 * @see MerkleOTSPrivateKey
 * @see MerkleOTSPublicKey
 */
public class MerkleOTSKeyFactory extends KeyFactory {

    /**
     * The OID of MerkleOTS.
     */
    public static final String OID = "1.3.6.1.4.1.8301.3.1.3.1.1";

    /**
     * Converts, if possible, a key specification into a
     * {@link MerkleOTSPublicKey}. Currently, the following key specifications
     * are supported: {@link MerkleOTSPublicKeySpec}.
     * 
     * @param keySpec
     *                the key specification
     * @return a public Merkle OTS key
     * @throws InvalidKeySpecException
     *                 if the KeySpec is not supported.
     * @see MerkleOTSPublicKey
     */
    public PublicKey generatePublic(KeySpec keySpec)
	    throws InvalidKeySpecException {
	if (keySpec instanceof MerkleOTSPublicKeySpec) {
	    MerkleOTSPublicKeySpec pubKeySpec = (MerkleOTSPublicKeySpec) keySpec;
	    return new MerkleOTSPublicKey(pubKeySpec.getOIDString(), pubKeySpec
		    .getKeyBytes());
	} else if (keySpec instanceof X509EncodedKeySpec) {

	    // get the DER-encoded key according to X.509 from the spec
	    byte[] encKey = ((X509EncodedKeySpec) keySpec).getEncoded();

	    // decode the SubjectPublicKeyInfo data structure to the pki object
	    SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo();
	    try {
		ASN1Tools.derDecode(encKey, spki);
	    } catch (Exception ce) {
		throw new InvalidKeySpecException(
			"Unable to decode X509EncodedKeySpec.");
	    }

	    try {
		// build and return the actual key
		ASN1Sequence pubKey = (ASN1Sequence) spki.getDecodedRawKey();

		// decode oidString
		String oidString = ((ASN1ObjectIdentifier) pubKey.get(0))
			.toString();

		// decode public key bytes
		ASN1Sequence keySequence = (ASN1Sequence) pubKey.get(1);
		byte[][] pubKeyBytes = new byte[keySequence.size()][];
		for (int i = 0; i < pubKeyBytes.length; i++) {
		    pubKeyBytes[i] = ((ASN1OctetString) keySequence.get(i))
			    .getByteArray();
		}

		return new MerkleOTSPublicKey(oidString, pubKeyBytes);

	    } catch (CorruptedCodeException cce) {
		throw new InvalidKeySpecException(
			"Unable to decode X509EncodedKeySpec.");
	    }
	}

	throw new InvalidKeySpecException("Unknown KeySpec type.");
    }

    /**
     * Converts, if possible, a key specification into a
     * {@link MerkleOTSPrivateKey}. Currently, the following key specifications
     * are supported: {@link MerkleOTSPrivateKeySpec}.
     * 
     * @param keySpec
     *                the key specification
     * @return a private Merkle OTS key
     * @throws InvalidKeySpecException
     *                 if the KeySpec is not supported.
     * @see MerkleOTSPrivateKey
     */
    public PrivateKey generatePrivate(KeySpec keySpec)
	    throws InvalidKeySpecException {
	if (keySpec instanceof MerkleOTSPrivateKeySpec) {
	    MerkleOTSPrivateKeySpec privKeySpec = (MerkleOTSPrivateKeySpec) keySpec;
	    return new MerkleOTSPrivateKey(privKeySpec.getOIDString(),
		    privKeySpec.getKeyBytes());
	} else if (keySpec instanceof PKCS8EncodedKeySpec) {

	    // get the DER-encoded key according to PKCS#8 from the spec
	    byte[] encKey = ((PKCS8EncodedKeySpec) keySpec).getEncoded();

	    // decode the PKCS#8 data structure to the pki object
	    PrivateKeyInfo pki = new PrivateKeyInfo();
	    try {
		ASN1Tools.derDecode(encKey, pki);
	    } catch (Exception ce) {
		throw new InvalidKeySpecException(
			"Unable to decode PKCS8EncodedKeySpec.");
	    }

	    try {
		// build and return the actual key
		ASN1Sequence privKey = (ASN1Sequence) pki.getDecodedRawKey();

		// decode oidString
		String oidString = ((ASN1ObjectIdentifier) privKey.get(0))
			.toString();

		// decode private key bytes
		ASN1Sequence keySequence = (ASN1Sequence) privKey.get(1);
		byte[][] privKeyBytes = new byte[keySequence.size()][];
		for (int i = 0; i < privKeyBytes.length; i++) {
		    privKeyBytes[i] = ((ASN1OctetString) keySequence.get(i))
			    .getByteArray();
		}

		return new MerkleOTSPrivateKey(oidString, privKeyBytes);

	    } catch (CorruptedCodeException cce) {
		throw new InvalidKeySpecException(
			"Unable to decode PKCS8EncodedKeySpec.");
	    }
	}
	throw new InvalidKeySpecException("Unknown KeySpec type.");
    }

    /**
     * Converts a given key into a key specification, if possible. Currently the
     * following specifications are supported:
     * <UL>
     * <LI> for MerkleOTSPublicKey: X509EncodedKeySpec, OTSKeySpec
     * <LI> for OTSPrivateKey: PKCS8EncodedKeySpec, OTSKeySpec.
     * </UL>
     * <p>
     * 
     * @see MerkleOTSPrivateKey
     * @see MerkleOTSPublicKey
     * @param key
     *                the key.
     * @param spec
     *                the class of which type the returned class should be.
     * @return OTSKeySpec the specification of the MerkleOTS key.
     * @throws InvalidKeySpecException
     *                 if the specification is not supported.
     */
    public KeySpec getKeySpec(Key key, Class spec)
	    throws InvalidKeySpecException {
	if (key instanceof MerkleOTSPrivateKey) {
	    MerkleOTSPrivateKey privKey = (MerkleOTSPrivateKey) key;
	    if (PKCS8EncodedKeySpec.class.isAssignableFrom(spec)) {
		return new PKCS8EncodedKeySpec(key.getEncoded());
	    } else if (MerkleOTSPrivateKeySpec.class.isAssignableFrom(spec)) {
		return new MerkleOTSPrivateKeySpec(privKey.getOIDString(),
			privKey.getKeyBytes());
	    }
	} else if (key instanceof MerkleOTSPublicKey) {
	    if (X509EncodedKeySpec.class.isAssignableFrom(spec)) {
		return new X509EncodedKeySpec(key.getEncoded());
	    } else if (MerkleOTSPublicKeySpec.class.isAssignableFrom(spec)) {
		MerkleOTSPublicKey pubKey = (MerkleOTSPublicKey) key;
		return new MerkleOTSPublicKeySpec(pubKey.getOIDString(), pubKey
			.getKeyBytes());
	    }
	}
	throw new InvalidKeySpecException("Unknown KeySpec.");
    }

    /**
     * Translates a key into a form known by the FlexiProvider. Currently the
     * following "source" keys are supported: OTSPrivateKey, MerkleOTSPublicKey.
     * 
     * @param key
     *                the key.
     * @return a key of a known key type.
     * @throws InvalidKeyException
     *                 if the key is not supported.
     */
    public Key translateKey(Key key) throws InvalidKeyException {
	if (key instanceof MerkleOTSPrivateKey) {
	    return key;
	} else if (key instanceof MerkleOTSPublicKey) {
	    return key;
	}

	throw new InvalidKeyException("Unsupported key type.");
    }
}
