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
 * This class is used to translate between McEliece CCA2 keys and key
 * specifications.
 * 
 * @author Elena Klintsevich
 * @author Martin Döring
 * @see McElieceCCA2PrivateKey
 * @see McElieceCCA2PrivateKeySpec
 * @see McElieceCCA2PublicKey
 * @see McElieceCCA2PublicKeySpec
 */
public class McElieceCCA2KeyFactory extends KeyFactory {

    /**
     * The OID of the algorithm.
     */
    public static final String OID = "1.3.6.1.4.1.8301.3.1.3.4.2";

    /**
     * Converts, if possible, a key specification into a
     * {@link McElieceCCA2PublicKey}. Currently, the following key
     * specifications are supported: {@link McElieceCCA2PublicKeySpec},
     * {@link X509EncodedKeySpec}.
     * 
     * @param keySpec
     *                the key specification
     * @return the McEliece CCA2 public key
     * @throws InvalidKeySpecException
     *                 if the key specification is not supported.
     */
    public PublicKey generatePublic(KeySpec keySpec)
	    throws InvalidKeySpecException {
	if (keySpec instanceof McElieceCCA2PublicKeySpec) {
	    return new McElieceCCA2PublicKey(
		    (McElieceCCA2PublicKeySpec) keySpec);
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

		return new McElieceCCA2PublicKey(new McElieceCCA2PublicKeySpec(
			t, n, matrixG));
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
     * {@link McElieceCCA2PrivateKey}. Currently, the following key
     * specifications are supported: {@link McElieceCCA2PrivateKeySpec},
     * {@link PKCS8EncodedKeySpec}.
     * 
     * @param keySpec
     *                the key specification
     * @return the McEliece CCA2 private key
     * @throws InvalidKeySpecException
     *                 if the KeySpec is not supported.
     */
    public PrivateKey generatePrivate(KeySpec keySpec)
	    throws InvalidKeySpecException {
	if (keySpec instanceof McElieceCCA2PrivateKeySpec) {
	    return new McElieceCCA2PrivateKey(
		    (McElieceCCA2PrivateKeySpec) keySpec);
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
		// decode <k>
		int k = ASN1Tools.getFlexiBigInt((ASN1Integer) privKey.get(1))
			.intValue();
		// decode <fieldPoly>
		byte[] encFieldPoly = ((ASN1OctetString) privKey.get(2))
			.getByteArray();
		// decode <goppaPoly>
		byte[] encGoppaPoly = ((ASN1OctetString) privKey.get(3))
			.getByteArray();
		// decode <p>
		byte[] encP = ((ASN1OctetString) privKey.get(4)).getByteArray();
		// decode <h>
		byte[] encH = ((ASN1OctetString) privKey.get(5)).getByteArray();
		// decode <qInv>
		ASN1Sequence qSeq = (ASN1Sequence) privKey.get(6);
		byte[][] encQInv = new byte[qSeq.size()][];
		for (int i = 0; i < qSeq.size(); i++) {
		    encQInv[i] = ((ASN1OctetString) qSeq.get(i)).getByteArray();
		}

		return new McElieceCCA2PrivateKey(
			new McElieceCCA2PrivateKeySpec(n, k, encFieldPoly,
				encGoppaPoly, encP, encH, encQInv));

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
     * <li>for McElieceCCA2PublicKey: {@link X509EncodedKeySpec},
     * {@link McElieceCCA2PublicKeySpec}</li>
     * <li>for McElieceCCA2PrivateKey: {@link PKCS8EncodedKeySpec},
     * {@link McElieceCCA2PrivateKeySpec}</li>.
     * </ul>
     * 
     * @param key
     *                the key
     * @param keySpec
     *                the key specification
     * @return the specification of the McEliece CCA2 key
     * @throws InvalidKeySpecException
     *                 if the key type or the key specification is not
     *                 supported.
     * @see McElieceCCA2PrivateKey
     * @see McElieceCCA2PrivateKeySpec
     * @see McElieceCCA2PublicKey
     * @see McElieceCCA2PublicKeySpec
     */
    public KeySpec getKeySpec(Key key, Class keySpec)
	    throws InvalidKeySpecException {
	if (key instanceof McElieceCCA2PrivateKey) {
	    if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec)) {
		return new PKCS8EncodedKeySpec(key.getEncoded());
	    } else if (McElieceCCA2PrivateKeySpec.class
		    .isAssignableFrom(keySpec)) {
		McElieceCCA2PrivateKey privKey = (McElieceCCA2PrivateKey) key;
		return new McElieceCCA2PrivateKeySpec(privKey.getN(), privKey
			.getK(), privKey.getField(), privKey.getGoppaPoly(),
			privKey.getP(), privKey.getH(), privKey.getQInv());
	    }
	} else if (key instanceof McElieceCCA2PublicKey) {
	    if (X509EncodedKeySpec.class.isAssignableFrom(keySpec)) {
		return new X509EncodedKeySpec(key.getEncoded());
	    } else if (McElieceCCA2PublicKeySpec.class
		    .isAssignableFrom(keySpec)) {
		McElieceCCA2PublicKey pubKey = (McElieceCCA2PublicKey) key;
		return new McElieceCCA2PublicKeySpec(pubKey.getN(), pubKey
			.getT(), pubKey.getG());
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
     * the following "source" keys are supported: {@link McElieceCCA2PrivateKey},
     * {@link McElieceCCA2PublicKey}.
     * 
     * @param key
     *                the key
     * @return a key of a known key type
     * @throws InvalidKeyException
     *                 if the key type is not supported.
     */
    public Key translateKey(Key key) throws InvalidKeyException {
	if ((key instanceof McElieceCCA2PrivateKey)
		|| (key instanceof McElieceCCA2PublicKey)) {
	    return key;
	}
	throw new InvalidKeyException("Unsupported key type.");

    }

}
