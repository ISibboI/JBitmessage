package de.flexiprovider.pqc.hbc.cmss;

import codec.CorruptedCodeException;
import codec.asn1.ASN1Integer;
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
 * This class transforms CMSS2 keys and CMSS2 key specifications into a form
 * that can be used with the FlexiPQCProvider.
 * 
 * @author Elena Klintsevich
 * @see de.flexiprovider.pqc.hbc.cmss2.CMSSPrivateKey
 * @see de.flexiprovider.pqc.hbc.cmss2.CMSSPrivateKeySpec
 * @see de.flexiprovider.pqc.hbc.cmss2.CMSSPublicKey
 * @see de.flexiprovider.pqc.hbc.cmss2.CMSSPublicKeySpec
 * @see KeyFactory
 */
public class CMSSKeyFactory extends KeyFactory {

    /**
     * The OID of CMSS2
     */
    public static final String OID = "1.3.6.1.4.1.8301.3.1.3.2";

    /**
     * Converts, if possible, a key specification into a CMSSPublicKey.
     * Currently, the following key specifications are supported:
     * CMSSPublicKeySpec, X509EncodedKeySpec.
     * 
     * @param keySpec
     *                the key specification
     * @return a CMSS2 public key
     * @throws InvalidKeySpecException
     *                 if the KeySpec is not supported.
     */
    public final PublicKey generatePublic(KeySpec keySpec)
	    throws InvalidKeySpecException {
	if (keySpec instanceof CMSSPublicKeySpec) {
	    return new CMSSPublicKey((CMSSPublicKeySpec) keySpec);
	} else if (keySpec instanceof X509EncodedKeySpec) {
	    // get the DER-encoded Key according to X.509 from the spec
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
		byte[] pubKeyBytes = ((ASN1OctetString) pubKey.get(1))
			.getByteArray();

		// decode masks
		byte[][][] masks = null;
		ASN1Sequence leftMasks = (ASN1Sequence) pubKey.get(2);
		ASN1Sequence rightMasks = (ASN1Sequence) pubKey.get(3);
		if (!leftMasks.isEmpty() && !rightMasks.isEmpty()) {
		    masks = new byte[leftMasks.size()][2][];
		    for (int i = 0; i < masks.length; i++) {
			masks[i][0] = ((ASN1OctetString) leftMasks.get(i))
				.getByteArray();
			masks[i][1] = ((ASN1OctetString) rightMasks.get(i))
				.getByteArray();
		    }
		}

		return new CMSSPublicKey(oidString, pubKeyBytes, masks);

	    } catch (CorruptedCodeException cce) {
		throw new InvalidKeySpecException(
			"Unable to decode X509EncodedKeySpec: "
				+ cce.getMessage());
	    }
	}

	throw new InvalidKeySpecException("Unknown key specification: "
		+ keySpec + ".");
    }

    /**
     * Converts, if possible, a key specification into a CMSSPrivateKey.
     * Currently the following key specs are supported: CMSSPrivateKeySpec.
     * 
     * @param keySpec -
     *                the key specification
     * @return a CMSS2 private key
     * @throws InvalidKeySpecException
     *                 if the KeySpec is not supported.
     * @see de.flexiprovider.pqc.hbc.cmss2.CMSSPrivateKey
     * @see de.flexiprovider.pqc.hbc.cmss2.CMSSPrivateKeySpec
     */
    public final PrivateKey generatePrivate(KeySpec keySpec)
	    throws InvalidKeySpecException {
	if (keySpec instanceof CMSSPrivateKeySpec) {
	    return new CMSSPrivateKey((CMSSPrivateKeySpec) keySpec);
	} else if (keySpec instanceof PKCS8EncodedKeySpec) {

	    // get the DER-encoded Key according to PKCS#8 from the spec
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

		// decode <indexMain>
		int indexMain = ASN1Tools.getFlexiBigInt(
			(ASN1Integer) privKey.get(1)).intValue();

		// decode <indexSub>
		int indexSub = ASN1Tools.getFlexiBigInt(
			(ASN1Integer) privKey.get(2)).intValue();

		// decode <heightOfTrees>
		int heightOfTrees = ASN1Tools.getFlexiBigInt(
			(ASN1Integer) privKey.get(3)).intValue();

		// decode <seeds>
		byte[][] seeds = new byte[3][];
		seeds[0] = ((ASN1OctetString) privKey.get(4)).getByteArray();
		seeds[1] = ((ASN1OctetString) privKey.get(5)).getByteArray();
		seeds[2] = ((ASN1OctetString) privKey.get(6)).getByteArray();

		// decode <authPaths>
		BDSAuthPath[] authPath = new BDSAuthPath[3];

		authPath[0] = new BDSAuthPath((ASN1Sequence) privKey.get(7));
		authPath[1] = new BDSAuthPath((ASN1Sequence) privKey.get(8));
		authPath[2] = new BDSAuthPath((ASN1Sequence) privKey.get(9));

		int activeSubtree = ASN1Tools.getFlexiBigInt(
			(ASN1Integer) privKey.get(10)).intValue();

		// decode <subtreeRootSig>
		byte[] subtreeRootSig = ((ASN1OctetString) privKey.get(11))
			.getByteArray();

		byte[] maintreeOTSVerificationKey = ((ASN1OctetString) privKey
			.get(12)).getByteArray();
		if (maintreeOTSVerificationKey.length == 0)
		    maintreeOTSVerificationKey = null;

		// decode masks
		byte[][][] masks = null;
		ASN1Sequence leftMasks = (ASN1Sequence) privKey.get(13);
		ASN1Sequence rightMasks = (ASN1Sequence) privKey.get(14);
		if (!leftMasks.isEmpty() && !rightMasks.isEmpty()) {
		    masks = new byte[leftMasks.size()][2][];
		    for (int i = 0; i < masks.length; i++) {
			masks[i][0] = ((ASN1OctetString) leftMasks.get(i))
				.getByteArray();
			masks[i][1] = ((ASN1OctetString) rightMasks.get(i))
				.getByteArray();
		    }
		}

		return new CMSSPrivateKey(oidString, indexMain, indexSub,
			heightOfTrees, seeds, authPath, activeSubtree,
			subtreeRootSig, maintreeOTSVerificationKey, masks);

	    } catch (CorruptedCodeException cce) {
		throw new InvalidKeySpecException(
			"Unable to decode PKCS8EncodedKeySpec: "
				+ cce.getMessage());
	    }
	}

	throw new InvalidKeySpecException("Unknown key specification: "
		+ keySpec + ".");
    }

    /**
     * Converts a given key into a key specification, if possible. Currently the
     * following specs are supported:
     * <ul>
     * <li> for CMSSPublicKey: X509EncodedKeySpec, CMSSPublicKeySpec
     * <li> for CMSSPrivateKey: PKCS8EncodedKeySpec, CMSSPrivateKeySpec
     * </ul>
     * 
     * @param key
     *                the key
     * @param keySpec
     *                the key specification
     * @return the specification of the CMSS2 key
     * @throws InvalidKeySpecException
     *                 if the key type or key specification is not supported.
     * @see de.flexiprovider.pqc.hbc.cmss2.CMSSPrivateKey
     * @see de.flexiprovider.pqc.hbc.cmss2.CMSSPrivateKeySpec
     * @see de.flexiprovider.pqc.hbc.cmss2.CMSSPublicKey
     * @see de.flexiprovider.pqc.hbc.cmss2.CMSSPublicKeySpec
     */
    public final KeySpec getKeySpec(Key key, Class keySpec)
	    throws InvalidKeySpecException {
	if (key instanceof CMSSPrivateKey) {
	    if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec)) {
		return new PKCS8EncodedKeySpec(key.getEncoded());
	    } else if (CMSSPrivateKeySpec.class.isAssignableFrom(keySpec)) {
		CMSSPrivateKey privKey = (CMSSPrivateKey) key;
		return new CMSSPrivateKeySpec(privKey.getOIDString(), privKey
			.getIndexMain(), privKey.getIndexSub(), privKey
			.getHeightOfTrees(), privKey.getSeeds(), privKey
			.getAuthPath(), privKey.getActiveSubtree(), privKey
			.getSubtreeRootSig(), privKey
			.getMaintreeOTSVerificationKey(), privKey.getMasks());
	    }
	} else if (key instanceof CMSSPublicKey) {
	    if (X509EncodedKeySpec.class.isAssignableFrom(keySpec)) {
		return new X509EncodedKeySpec(key.getEncoded());
	    } else if (CMSSPublicKeySpec.class.isAssignableFrom(keySpec)) {
		CMSSPublicKey pubKey = (CMSSPublicKey) key;
		return new CMSSPublicKeySpec(pubKey.getAlgorithm(), pubKey
			.getKeyBytes(), pubKey.getMasks());
	    }
	} else {
	    throw new InvalidKeySpecException("Unsupported key type: "
		    + key.getClass() + ".");
	}

	throw new InvalidKeySpecException("Unknown key specification: "
		+ keySpec + ".");
    }

    /**
     * Translates a key into a form known by the FlexiProvider. Currently the
     * following key types are supported: CMSSPrivateKey, CMSSPublicKey.
     * 
     * @param key
     *                the key
     * @return a key of a known key type
     * @throws InvalidKeyException
     *                 if the key is not supported.
     */
    public final Key translateKey(Key key) throws InvalidKeyException {
	if (key instanceof CMSSPrivateKey || key instanceof CMSSPublicKey) {
	    return key;
	}
	throw new InvalidKeyException("Unsupported key type");
    }

}
