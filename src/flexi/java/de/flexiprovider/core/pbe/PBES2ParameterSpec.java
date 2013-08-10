/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.pbe;

import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1OctetString;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.core.kdf.PBKDF2ParameterSpec;
import de.flexiprovider.core.kdf.PBKDF2Parameters;
import de.flexiprovider.pki.AlgorithmIdentifier;

/**
 * This is the parameter specification for the
 * {@link de.flexiprovider.core.pbe.PBES2 passphrase based encryption scheme 2}.
 * 
 * @author Thomas Wahrenbruch
 */
public class PBES2ParameterSpec implements AlgorithmParameterSpec {

    /**
     * the AlgorithmIdentifier of the key derivation function
     */
    private AlgorithmIdentifier keyDerivationFunction;

    /**
     * the AlgorithmIdentifier of the encryption scheme
     */
    private AlgorithmIdentifier encryptionScheme;

    /**
     * Construct a new PBE2ParameterSpec object with cipher
     * {@link de.flexiprovider.core.desede.DESede.DESede_CBC DESede/CBC} (OID
     * 1.2.840.113549.3.7) and the default key derivation function
     * {@link de.flexiprovider.core.kdf.PBKDF2} (OID 1.2.840.113549.1.5.12).
     * 
     * @param kdfParamSpec
     *                the KDF parameters (salt, iteration count, and key size)
     * @param iv
     *                the initialization vector for the underlying cipher
     */
    public PBES2ParameterSpec(PBKDF2ParameterSpec kdfParamSpec, byte[] iv) {
	try {
	    PBKDF2Parameters kdfParams = new PBKDF2Parameters();
	    kdfParams.init(kdfParamSpec);
	    ASN1ObjectIdentifier kdfOID = new ASN1ObjectIdentifier(
		    "1.2.840.113549.1.5.12");
	    keyDerivationFunction = new AlgorithmIdentifier(kdfOID, kdfParams
		    .getEncoded());

	    ASN1ObjectIdentifier cipherOID = new ASN1ObjectIdentifier(
		    "1.2.840.113549.3.7");
	    encryptionScheme = new AlgorithmIdentifier(cipherOID,
		    new ASN1OctetString(iv));
	} catch (Exception e) {
	    throw new RuntimeException("Internal error: " + e.getMessage());
	}
    }

    /**
     * Construct a new PBE2ParameterSpec object.
     * 
     * @param keyDerivationFunction
     *                the key derivation function
     * @param encryptionScheme
     *                the encryption scheme
     */
    protected PBES2ParameterSpec(AlgorithmIdentifier keyDerivationFunction,
	    AlgorithmIdentifier encryptionScheme) {

	this.keyDerivationFunction = keyDerivationFunction;
	this.encryptionScheme = encryptionScheme;
    }

    /**
     * @return the AlgorithmIdentifier of the encryption scheme
     */
    public AlgorithmIdentifier getEncryptionScheme() {
	return encryptionScheme;
    }

    /**
     * @return the AlgorithmIdentifier of key derivation function.
     */
    public AlgorithmIdentifier getKeyDerivationFunction() {
	return keyDerivationFunction;
    }

}
