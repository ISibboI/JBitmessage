package de.flexiprovider.pqc.ecc.niederreiter;

import codec.CorruptedCodeException;
import codec.asn1.ASN1Integer;
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
 * This class is used to translate between Niederreiter keys and key
 * specifications.
 * 
 * @author Elena Klintsevich
 * @author Martin Döring
 * @see NiederreiterPrivateKey
 * @see NiederreiterPrivateKeySpec
 * @see NiederreiterPublicKey
 * @see NiederreiterPublicKeySpec
 */
public class NiederreiterKeyFactory extends KeyFactory {

    /**
     * The OID of the algorithm.
     */
    public static final String OID = "1.3.6.1.4.1.8301.3.1.3.4.3";

    /**
     * Converts, if possible, a key specification into a NiederreiterPublicKey.
     * Currently, the following key specifications are supported:
     * NiederreiterPublicKeySpec.
     * 
     * @param keySpec
     *                the key specification
     * @return the public Niederreiter key
     * @throws InvalidKeySpecException
     *                 if the KeySpec is not supported.
     * @see de.flexiprovider.pqc.ecc.niederreiter.NiederreiterPublicKey
     * @see de.flexiprovider.pqc.ecc.niederreiter.NiederreiterPublicKeySpec
     */
    public PublicKey generatePublic(KeySpec keySpec)
	    throws InvalidKeySpecException {
	if (keySpec instanceof NiederreiterPublicKeySpec) {
	    return new NiederreiterPublicKey(
		    (NiederreiterPublicKeySpec) keySpec);
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

		// decode <n>
		int n = ASN1Tools.getFlexiBigInt((ASN1Integer) pubKey.get(0))
			.intValue();

		// decode <t>
		int t = ASN1Tools.getFlexiBigInt((ASN1Integer) pubKey.get(1))
			.intValue();

		// decode <matrixH>
		byte[] matrixH = ((ASN1OctetString) pubKey.get(2))
			.getByteArray();

		return new NiederreiterPublicKey(new NiederreiterPublicKeySpec(
			n, t, matrixH));

	    } catch (CorruptedCodeException cce) {
		throw new InvalidKeySpecException(
			"Unable to decode X509EncodedKeySpec.");
	    }
	}

	throw new InvalidKeySpecException("Unknown key specification: "
		+ keySpec + ".");
    }

    /**
     * Converts, if possible, a key specification into a NiederreiterPrivateKey.
     * Currently, the following key specifications are supported:
     * NiederreiterPrivateKeySpec.
     * 
     * @param keySpec
     *                the key specification
     * @return the private Niederreiter key
     * @throws InvalidKeySpecException
     *                 if the KeySpec is not supported.
     * @see de.flexiprovider.pqc.ecc.niederreiter.NiederreiterPrivateKey
     * @see de.flexiprovider.pqc.ecc.niederreiter.NiederreiterPrivateKeySpec
     */
    public PrivateKey generatePrivate(KeySpec keySpec)
	    throws InvalidKeySpecException {
	if (keySpec instanceof NiederreiterPrivateKeySpec) {
	    return new NiederreiterPrivateKey(
		    (NiederreiterPrivateKeySpec) keySpec);
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

		// decode <m>
		int m = ASN1Tools.getFlexiBigInt((ASN1Integer) privKey.get(0))
			.intValue();
		// decode <k>
		int k = ASN1Tools.getFlexiBigInt((ASN1Integer) privKey.get(1))
			.intValue();
		// decode <field>
		byte[] encField = ((ASN1OctetString) privKey.get(2))
			.getByteArray();
		// decode <goppaPoly>
		byte[] encIrrGoppaPoly = ((ASN1OctetString) privKey.get(3))
			.getByteArray();
		// decode <sInv>
		byte[] encSInv = ((ASN1OctetString) privKey.get(4))
			.getByteArray();
		// decode <p>
		byte[] encP = ((ASN1OctetString) privKey.get(5)).getByteArray();
		// decode <qInv>
		ASN1Sequence qInvSeq = (ASN1Sequence) privKey.get(6);
		byte[][] encQInv = new byte[qInvSeq.size()][];
		for (int i = 0; i < qInvSeq.size(); i++) {
		    encQInv[i] = ((ASN1OctetString) qInvSeq.get(i))
			    .getByteArray();
		}

		return new NiederreiterPrivateKey(
			new NiederreiterPrivateKeySpec(m, k, encField,
				encIrrGoppaPoly, encSInv, encP, encQInv));

	    } catch (CorruptedCodeException cce) {
		throw new InvalidKeySpecException(
			"Unable to decode PKCS8EncodedKeySpec.");
	    }
	}

	throw new InvalidKeySpecException("Unknown key specification: "
		+ keySpec + ".");
    }

    /**
     * Converts, if possible, a given key into a key specification. Currently,
     * the following specifications are supported:
     * <ul>
     * <li> for NiederreiterPublicKey: X509EncodedKeySpec,
     * NiederreiterPublicKeySpec</li>
     * <li> for NiederreiterPrivateKey: PKCS8EncodedKeySpec,
     * NiederreiterPrivateKeySpec</li>
     * </ul>
     * 
     * @param key
     *                the key
     * @param keySpec
     *                the class of which type the returned class should be.
     * @return the specification of the Niederreiter key
     * @throws InvalidKeySpecException
     *                 if the key type or key specification is not supported.
     * @see de.flexiprovider.pqc.ecc.niederreiter.NiederreiterPrivateKey
     * @see de.flexiprovider.pqc.ecc.niederreiter.NiederreiterPrivateKeySpec
     * @see de.flexiprovider.pqc.ecc.niederreiter.NiederreiterPublicKey
     * @see de.flexiprovider.pqc.ecc.niederreiter.NiederreiterPublicKeySpec
     */
    public KeySpec getKeySpec(Key key, Class keySpec)
	    throws InvalidKeySpecException {
	if (key instanceof NiederreiterPrivateKey) {
	    if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec)) {
		return new PKCS8EncodedKeySpec(key.getEncoded());
	    } else if (NiederreiterPrivateKeySpec.class
		    .isAssignableFrom(keySpec)) {
		NiederreiterPrivateKey privKey = (NiederreiterPrivateKey) key;
		return new NiederreiterPrivateKeySpec(privKey.getM(), privKey
			.getK(), privKey.getField(), privKey.getGoppaPoly(),
			privKey.getSInv(), privKey.getP(), privKey.getQInv());
	    }
	} else if (key instanceof NiederreiterPublicKey) {
	    if (X509EncodedKeySpec.class.isAssignableFrom(keySpec)) {
		return new X509EncodedKeySpec(key.getEncoded());
	    } else if (NiederreiterPublicKeySpec.class
		    .isAssignableFrom(keySpec)) {
		NiederreiterPublicKey pubKey = (NiederreiterPublicKey) key;
		return new NiederreiterPublicKeySpec(pubKey.getN(), pubKey
			.getT(), pubKey.getH());
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
     * following "source" keys are supported: NiederreiterPrivateKey,
     * NiederreiterPublicKey.
     * 
     * @param key
     *                the key
     * @return a key of a known key type
     * @throws InvalidKeyException
     *                 if the key type is not supported.
     */
    public Key translateKey(Key key) throws InvalidKeyException {
	if (key instanceof NiederreiterPrivateKey
		|| key instanceof NiederreiterPublicKey) {
	    return key;
	}
	throw new InvalidKeyException("Unsupported key type: " + key.getClass()
		+ ".");
    }

}
