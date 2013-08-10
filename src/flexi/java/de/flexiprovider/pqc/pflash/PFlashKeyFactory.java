package de.flexiprovider.pqc.pflash;

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
import de.flexiprovider.pqc.pflash.PFlashPrivateKey;
import de.flexiprovider.pqc.pflash.PFlashPublicKey;

/**
 * This class is able to transform pFLASH keys and pFLASH key specifications
 * into a form that can be used with the FlexiPQCProvider.
 * 
 * @author Marian Hornschuch, Alexander Koller
 * @see {@link PFlashPrivateKey}
 * @see {@link PFlashPrivateKeySpec}
 * @see {@link PFlashPublicKey}
 * @see {@link PFlashPubicKeySpec}
 * @see {@link KeyFactory}
 */
public class PFlashKeyFactory extends KeyFactory {

   /**
    * The OID of pFLASH
    */
    public static final String OID = "1.3.6.1.4.1.8301.3.1.3.5.3.3";
    
    /**
     * Converts, if possible, a key specification into a {@link PFlashPublicKey}.
     * Currently, the following key specifications are supported:
     * {@link PFlashPublicKeySpec}.
     * 
     * @param keySpec
     *                the key specification
     * @return the public pFLASH key
     * @throws InvalidKeySpecException
     *                 if the KeySpec is not supported.
     * @see {@link PFlashPublicKey}
     * @see {@link PFlashPublicKeySpec}
     */
    public PublicKey generatePublic(KeySpec keySpec)
    		throws InvalidKeySpecException {
	if (keySpec instanceof PFlashPublicKeySpec) {
	    return new PFlashPublicKey(
		    (PFlashPublicKeySpec) keySpec);
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
		ASN1Sequence publicKey = (ASN1Sequence) spki.getDecodedRawKey();
		
		// decode FIXME: pubBytes
		
		//return new PFlashPublicKey(FIXME);
	    } catch (CorruptedCodeException cce) {
		throw new InvalidKeySpecException(
			"Unable to decode X509EncodedKeySpec.");
	    }
	}
	
	throw new InvalidKeySpecException("Unkown key specification: "
		+ keySpec + ".");
    }
    
    /**
     * Converts, if possible, a key specification into a {@link PFlashPrivateKey}.
     * Currently, the following key specifications are supported:
     * {@link PFlashPrivateKeySpec}
     * 
     * @param keySpec
     *                the key specification
     * @return the private pFLASH key
     * @throws InvalidKeySpecException
     *                 if the KeySpec is not supported.
     * @see {@link PFlashPrivateKey}
     * @see {@link PFlashPrivateKeySpec}
     */
    public PrivateKey generatePrivate(KeySpec keySpec)
    		throws InvalidKeySpecException {
	if (keySpec instanceof PFlashPrivateKeySpec) {
	    return new PFlashPrivateKey(
		    (PFlashPrivateKeySpec) keySpec);
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
		ASN1Sequence privateKey = (ASN1Sequence) pki.getDecodedRawKey();
		
		// decode <m_S>
		byte[] m_S = ((ASN1OctetString) privateKey.get(0)).getByteArray();
		
		// decode <c_S>
		byte[] c_S = ((ASN1OctetString) privateKey.get(1)).getByteArray();
		
		// decode <m_T>
		byte[] m_T = ((ASN1OctetString) privateKey.get(2)).getByteArray();
		
		// decode <c_T>
		byte[] c_T = ((ASN1OctetString) privateKey.get(3)).getByteArray();
		
		// decode <poly_384>
		byte[] poly_384 = ((ASN1OctetString) privateKey.get(4)).getByteArray();
		
		return new PFlashPrivateKey(
			new PFlashPrivateKeySpec(m_S, c_S,
				m_T, c_T, poly_384));
		
	    } catch (CorruptedCodeException cce) {
		throw new InvalidKeySpecException(
			"Unable to decode PKCS8EncodedKeySpec.");
	    }
	}
	
	throw new InvalidKeySpecException("Unknown key specification: "
		+ keySpec + ".");
    }
    
    /**
     * Converts, if possible, a given key into a key specification.
     * Currently, the following specifications are supported:
     * <ul>
     * <li> for PFlashPublicKey: PFlashPublicKeySpec</li>
     * <li> for PFlashPrivateKey: PFlashPrivateKeySpec</li>
     * </ul>
     * 
     * @param key
     *                the key
     * @param keySpec
     *                the class of which type the returned class should be.
     * @return the specification of the pFLASH key
     * @throws InvalidKeySpecException
     *                 if the key type or key specification is not supported.
     * @see {@link PFlashPrivateKey}
     * @see {@link PFlashPrivateKeySpec}
     * @see {@link PFlashPublicKey}
     * @see {@link PFlashPublicKeySpec}
     */
    public KeySpec getKeySpec(Key key, Class keySpec)
    		throws InvalidKeySpecException {
	if (key instanceof PFlashPrivateKey) {
	    if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec)) {
		return new PKCS8EncodedKeySpec(key.getEncoded());
	    } else if (PFlashPrivateKeySpec.class.isAssignableFrom(keySpec)) {
		PFlashPrivateKey privateKey = (PFlashPrivateKey) key;
		return new PFlashPrivateKeySpec(privateKey.getM_S(),privateKey.getC_S(),
			privateKey.getM_S(),privateKey.getC_T(),privateKey.getPoly_384());
	    }
	} else if (key instanceof PFlashPublicKey) {
	    if (X509EncodedKeySpec.class.isAssignableFrom(keySpec)) {
		return new X509EncodedKeySpec(key.getEncoded());
	    } else if (PFlashPublicKeySpec.class.isAssignableFrom(keySpec)) {
		PFlashPublicKey publicKey = (PFlashPublicKey) key;
		//return new PFlashPublicKeySpec(publicKey.get FIXME: KEYBYES);
	    }
	} else {
	    throw new InvalidKeySpecException("Unsupported key type: "
		    + key.getClass() + ".");
	}
	
	throw new InvalidKeySpecException("Unknown key specification: "
		+ keySpec + ".");
    }

    /**
     * Translates a key into a form known by the FlexiProvider.
     * Currently the following "source" keys are supported:
     * PFlashPrivateKey, PFlashPublicKey.
     * 
     * @param key
     *                the key
     * @return a key of a known key type
     * @throws InvalidKeyException
     *                 if the key type is not supported.
     */
    public Key translateKey(Key key) throws InvalidKeyException {
	if (key instanceof PFlashPrivateKey
		|| key instanceof PFlashPublicKey) {
	    return key;
	}
	throw new InvalidKeyException("Unsupported key type: "
		+ key.getClass() + ".");
    }
}
