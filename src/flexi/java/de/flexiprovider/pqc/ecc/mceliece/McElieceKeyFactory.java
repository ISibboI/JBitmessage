package de.flexiprovider.pqc.ecc.mceliece;

import codec.CorruptedCodeException;
import codec.asn1.ASN1Integer;
import codec.asn1.ASN1OctetString;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1Type;
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
 * This class is used to translate between McEliece keys and key specifications.
 * 
 * @author Elena Klintsevich
 * @author Martin Döring
 * @see McEliecePrivateKey
 * @see McEliecePrivateKeySpec
 * @see McEliecePublicKey
 * @see McEliecePublicKeySpec
 */
public class McElieceKeyFactory extends KeyFactory {

    /**
     * The OID of the algorithm.
     */
    public static final String OID = "1.3.6.1.4.1.8301.3.1.3.4.1";

    /**
     * Converts, if possible, a key specification into a
     * {@link McEliecePublicKey}. Currently, the following key specifications
     * are supported: {@link McEliecePublicKeySpec}, {@link X509EncodedKeySpec}.
     * 
     * @param keySpec
     *                the key specification
     * @return the McEliece public key
     * @throws InvalidKeySpecException
     *                 if the key specification is not supported.
     */
    public PublicKey generatePublic(KeySpec keySpec)
	    throws InvalidKeySpecException {
	if (keySpec instanceof McEliecePublicKeySpec) {
	    return new McEliecePublicKey((McEliecePublicKeySpec) keySpec);
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
		// --- Build and return the actual key.
		ASN1Sequence publicKey = (ASN1Sequence) spki.getDecodedRawKey();

		// decode <n>
		int n = ASN1Tools
			.getFlexiBigInt((ASN1Integer) publicKey.get(0))
			.intValue();

		// decode <t>
		int t = ASN1Tools
			.getFlexiBigInt((ASN1Integer) publicKey.get(1))
			.intValue();

		// decode <matrixG>
		byte[] matrixG = ((ASN1OctetString) publicKey.get(2))
			.getByteArray();

		return new McEliecePublicKey(new McEliecePublicKeySpec(t, n,
			matrixG));
	    } catch (CorruptedCodeException cce) {
		throw new InvalidKeySpecException(
			"Unable to decode X509EncodedKeySpec: "
				+ cce.getMessage());
	    }
	}

	throw new InvalidKeySpecException("Unsupported key specification: "
		+ keySpec.getClass() + ".");
    }

    /**
     * Converts, if possible, a key specification into a
     * {@link McEliecePrivateKey}. Currently, the following key specifications
     * are supported: {@link McEliecePrivateKeySpec},
     * {@link PKCS8EncodedKeySpec}.
     * 
     * @param keySpec
     *                the key specification
     * @return the McEliece private key
     * @throws InvalidKeySpecException
     *                 if the KeySpec is not supported.
     */
    public PrivateKey generatePrivate(KeySpec keySpec)
	    throws InvalidKeySpecException {
	if (keySpec instanceof McEliecePrivateKeySpec) {
	    return new McEliecePrivateKey((McEliecePrivateKeySpec) keySpec);
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
		// get the inner type inside the OCTET STRING
		ASN1Type innerType = pki.getDecodedRawKey();

		// build and return the actual key
		ASN1Sequence privKey = (ASN1Sequence) innerType;

		// decode <n>
		int n = ASN1Tools.getFlexiBigInt((ASN1Integer) privKey.get(0))
			.intValue();
		// decode <d>
		int k = ASN1Tools.getFlexiBigInt((ASN1Integer) privKey.get(1))
			.intValue();
		// decode <fieldPoly>
		byte[] encFieldPoly = ((ASN1OctetString) privKey.get(2))
			.getByteArray();
		// decode <goppaPoly>
		byte[] encGoppaPoly = ((ASN1OctetString) privKey.get(3))
			.getByteArray();
		// decode <sInv>
		byte[] encSInv = ((ASN1OctetString) privKey.get(4))
			.getByteArray();
		// decode <p1>
		byte[] encP1 = ((ASN1OctetString) privKey.get(5))
			.getByteArray();
		// decode <p2>
		byte[] encP2 = ((ASN1OctetString) privKey.get(6))
			.getByteArray();
		// decode <h>
		byte[] encH = ((ASN1OctetString) privKey.get(7)).getByteArray();
		// decode <qInv>
		ASN1Sequence qInvSeq = (ASN1Sequence) privKey.get(8);
		byte[][] encQInv = new byte[qInvSeq.size()][];
		for (int i = 0; i < qInvSeq.size(); i++) {
		    encQInv[i] = ((ASN1OctetString) qInvSeq.get(i))
			    .getByteArray();
		}

		return new McEliecePrivateKey(new McEliecePrivateKeySpec(n, k,
			encFieldPoly, encGoppaPoly, encSInv, encP1, encP2,
			encH, encQInv));

	    } catch (CorruptedCodeException cce) {
		throw new InvalidKeySpecException(
			"Unable to decode PKCS8EncodedKeySpec.");
	    }
	}

	throw new InvalidKeySpecException("Unsupported key specification: "
		+ keySpec.getClass() + ".");
    }

    /**
     * Converts, if possible, a given key into a key specification. Currently,
     * the following key specifications are supported:
     * <ul>
     * <li>for McEliecePublicKey: {@link X509EncodedKeySpec},
     * {@link McEliecePublicKeySpec}</li>
     * <li>for McEliecePrivateKey: {@link PKCS8EncodedKeySpec},
     * {@link McEliecePrivateKeySpec}</li>.
     * </ul>
     * 
     * @param key
     *                the key
     * @param keySpec
     *                the key specification
     * @return the specification of the McEliece key
     * @throws InvalidKeySpecException
     *                 if the key type or the key specification is not
     *                 supported.
     * @see McEliecePrivateKey
     * @see McEliecePrivateKeySpec
     * @see McEliecePublicKey
     * @see McEliecePublicKeySpec
     */
    public KeySpec getKeySpec(Key key, Class keySpec)
	    throws InvalidKeySpecException {
	if (key instanceof McEliecePrivateKey) {
	    if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec)) {
		return new PKCS8EncodedKeySpec(key.getEncoded());
	    } else if (McEliecePrivateKeySpec.class.isAssignableFrom(keySpec)) {
		McEliecePrivateKey privKey = (McEliecePrivateKey) key;
		return new McEliecePrivateKeySpec(privKey.getN(), privKey
			.getK(), privKey.getField(), privKey.getGoppaPoly(),
			privKey.getSInv(), privKey.getP1(), privKey.getP2(),
			privKey.getH(), privKey.getQInv());
	    }
	} else if (key instanceof McEliecePublicKey) {
	    if (X509EncodedKeySpec.class.isAssignableFrom(keySpec)) {
		return new X509EncodedKeySpec(key.getEncoded());
	    } else if (McEliecePublicKeySpec.class.isAssignableFrom(keySpec)) {
		McEliecePublicKey pubKey = (McEliecePublicKey) key;
		return new McEliecePublicKeySpec(pubKey.getN(), pubKey.getT(),
			pubKey.getG());
	    }
	} else {
	    throw new InvalidKeySpecException("Unsupported key type: "
		    + key.getClass() + ".");
	}

	throw new InvalidKeySpecException("Unknown key specification: "
		+ keySpec + ".");
    }

    /**
     * Translates a key into a form known by the FlexiProvider. Currently, only
     * the following "source" keys are supported: {@link McEliecePrivateKey},
     * {@link McEliecePublicKey}.
     * 
     * @param key
     *                the key
     * @return a key of a known key type
     * @throws InvalidKeyException
     *                 if the key type is not supported.
     */
    public Key translateKey(Key key) throws InvalidKeyException {
	if ((key instanceof McEliecePrivateKey)
		|| (key instanceof McEliecePublicKey)) {
	    return key;
	}
	throw new InvalidKeyException("Unsupported key type.");

    }

}
