package de.flexiprovider.pki;

import codec.asn1.ASN1ObjectIdentifier;
import codec.pkcs8.PrivateKeyInfo;
import codec.x509.SubjectPublicKeyInfo;

/**
 * PKI utility class. Used to get FlexiAPI objects from ASN.1 CoDec objects.
 * 
 * @author Martin Döring
 */
public final class PKITools {

    /**
     * Default constructor (private).
     */
    private PKITools() {
	// empty
    }

    /**
     * Get an {@link AlgorithmIdentifier} object from the given
     * {@link PrivateKeyInfo} structure.
     * 
     * @param pki
     *                the {@link PrivateKeyInfo} structure
     * @return the {@link AlgorithmIdentifier}
     */
    public static AlgorithmIdentifier getAlgorithmIdentifier(PrivateKeyInfo pki) {
	codec.x509.AlgorithmIdentifier algId = pki.getAlgorithmIdentifier();
	ASN1ObjectIdentifier algOID = algId.getAlgorithmOID();
	try {
	    java.security.AlgorithmParameters algParams = algId.getParameters();
	    if (algParams == null) {
		return new AlgorithmIdentifier(algOID, (byte[]) null);
	    }
	    byte[] encParams = algParams.getEncoded();
	    return new AlgorithmIdentifier(algOID, encParams);
	} catch (Exception e) {
	    throw new RuntimeException(e.getClass().getName() + ": "
		    + e.getMessage());
	}
    }

    /**
     * Get an {@link AlgorithmIdentifier} object from the given
     * {@link SubjectPublicKeyInfo} structure.
     * 
     * @param spki
     *                the {@link SubjectPublicKeyInfo} structure
     * @return the {@link AlgorithmIdentifier}
     */
    public static AlgorithmIdentifier getAlgorithmIdentifier(
	    SubjectPublicKeyInfo spki) {
	codec.x509.AlgorithmIdentifier algId = spki.getAlgorithmIdentifier();
	ASN1ObjectIdentifier algOID = algId.getAlgorithmOID();
	try {
	    java.security.AlgorithmParameters algParams = algId.getParameters();
	    if (algParams == null) {
		return new AlgorithmIdentifier(algOID, (byte[]) null);
	    }
	    byte[] encParams = algParams.getEncoded();
	    return new AlgorithmIdentifier(algOID, encParams);
	} catch (Exception e) {
	    throw new RuntimeException(e.getClass().getName() + ": "
		    + e.getMessage());
	}
    }

}
