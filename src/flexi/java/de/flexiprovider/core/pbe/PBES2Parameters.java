/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.pbe;

import java.io.IOException;

import codec.asn1.ASN1Exception;
import codec.asn1.ASN1Sequence;
import de.flexiprovider.api.exceptions.InvalidParameterSpecException;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.api.parameters.AlgorithmParameters;
import de.flexiprovider.common.util.ASN1Tools;
import de.flexiprovider.pki.AlgorithmIdentifier;

/**
 * This class represents the parameters for the
 * {@link de.flexiprovider.core.pbe.PBES2 passphrase based encryption scheme 2}.
 * 
 * @author Thomas Wahrenbruch
 */
public class PBES2Parameters extends AlgorithmParameters {

    /**
     * The reference to the AlgorithmIdentifier of the key derivation function.
     * 
     * @serial
     */
    private AlgorithmIdentifier keyDerivationFunction;

    /**
     * The reference to the AlgorithmIdentifier of the encryption scheme.
     * 
     * @serial
     */
    private AlgorithmIdentifier encryptionScheme;

    /**
     * Inner class providing the PBES2 ASN.1 parameters structure.
     * <p>
     * The ASN.1 parameters structure is defined as follows:
     * 
     * <pre>
     * PBES2-params ::= SEQUENCE {
     * 	 keyDerivationFunc AlgorithmIdentifier,
     *   encryptionScheme AlgorithmIdentifier
     * }
     * </pre>
     * 
     * @author Thomas Wahrenbruch
     * @author Martin Döring
     */
    private static class PBES2ASN1Params extends ASN1Sequence {

	// the algorithm identifier of the key derivation function
	private AlgorithmIdentifier keyDerivationFunction;

	// the algorithm identifier of the encryption scheme
	private AlgorithmIdentifier encryptionScheme;

	/**
	 * Construct the ASN.1 structure (used for decoding).
	 */
	public PBES2ASN1Params() {
	    super(2);
	    keyDerivationFunction = new AlgorithmIdentifier();
	    encryptionScheme = new AlgorithmIdentifier();

	    add(keyDerivationFunction);
	    add(encryptionScheme);
	}

	/**
	 * Construct an ASN.1 structure with the given parameters (used for
	 * encoding).
	 * 
	 * @param encScheme
	 *                the algorithm identifier of the encryption scheme
	 * @param keyDerivationFunction
	 *                the algorithm identifier of the key derivation
	 *                function
	 */
	public PBES2ASN1Params(AlgorithmIdentifier keyDerivationFunction,
		AlgorithmIdentifier encScheme) {
	    super(2);
	    this.keyDerivationFunction = keyDerivationFunction;
	    this.encryptionScheme = encScheme;

	    add(this.keyDerivationFunction);
	    add(this.encryptionScheme);
	}

	/**
	 * @return the algorithm identifier of the encryption scheme
	 */
	public AlgorithmIdentifier getEncryptionScheme() {
	    return encryptionScheme;
	}

	/**
	 * @return the algorithm identifier of the key derivation function
	 */
	public AlgorithmIdentifier getKeyDerivationFunction() {
	    return keyDerivationFunction;
	}
    }

    /**
     * Initialize the parameters with the given parameter specification.
     * Currently, only {@link PBES2ParameterSpec} is supported as specification
     * type.
     * 
     * @param params
     *                the parameter specification
     * @throws InvalidParameterSpecException
     *                 if the parameter specification is not an instance of
     *                 {@link PBES2ParameterSpec}.
     */
    public void init(AlgorithmParameterSpec params)
	    throws InvalidParameterSpecException {
	if (params instanceof PBES2ParameterSpec) {
	    PBES2ParameterSpec pbe2ParamSpec = (PBES2ParameterSpec) params;
	    keyDerivationFunction = pbe2ParamSpec.getKeyDerivationFunction();
	    encryptionScheme = pbe2ParamSpec.getEncryptionScheme();
	} else {
	    throw new InvalidParameterSpecException("parameters not supported");
	}
    }

    /**
     * Import the specified parameters and decode them according to the primary
     * decoding format. The primary decoding format for parameters is ASN.1.
     * 
     * @param encParams
     *                the encoded parameters
     * @throws IOException
     *                 on decoding errors.
     */
    public void init(byte[] encParams) throws IOException {
	try {
	    PBES2ASN1Params asn1pbe2Params = new PBES2ASN1Params();
	    ASN1Tools.derDecode(encParams, asn1pbe2Params);

	    keyDerivationFunction = asn1pbe2Params.getKeyDerivationFunction();
	    encryptionScheme = asn1pbe2Params.getEncryptionScheme();
	} catch (ASN1Exception e) {
	    throw new IOException("ASN1Exception: " + e.getMessage());
	}
    }

    /**
     * Import the specified parameters and decode them according to the
     * specified decoding format. Currently, only the primary decoding format
     * ("ASN.1") is supported.
     * 
     * @param encParams
     *                the encoded parameters
     * @param format
     *                the decoding format
     * @throws IOException
     *                 on decoding errors or if the encoding format is
     *                 unsupported.
     */
    public void init(byte[] encParams, String format) throws IOException {
	if ((format != null) && !format.equals("ASN.1")) {
	    throw new IOException("unsupported format");
	}
	init(encParams);
    }

    /**
     * Return the parameters encoded in their primary encoding format. The
     * primary encoding format for parameters is ASN.1.
     * 
     * @return the encoded parameters
     * @throws IOException
     *                 on encoding errors.
     */
    public byte[] getEncoded() throws IOException {
	PBES2ASN1Params asn1pbe2Params = new PBES2ASN1Params(
		keyDerivationFunction, encryptionScheme);

	try {
	    return ASN1Tools.derEncode(asn1pbe2Params);
	} catch (RuntimeException re) {
	    throw new IOException(re.getMessage());
	}
    }

    /**
     * Return the parameters encoded in the specified encoding format.
     * Currently, only the primary encoding format ("ASN.1") is supported.
     * 
     * @param format
     *                the decoding format
     * @return the encoded parameters
     * @throws IOException
     *                 on encoding errors or if the encoding format is
     *                 unsupported.
     */
    public byte[] getEncoded(String format) throws IOException {
	if (format == null) {
	    return getEncoded();
	}
	throw new IOException("decoding error - " + format + " not supported.");
    }

    /**
     * Return a transparent specification of the parameters. Currently, only
     * {@link PBES2ParameterSpec} is supported as specification type.
     * 
     * @param paramSpec
     *                the desired parameter specification type
     * @return the parameter specification
     * @throws InvalidParameterSpecException
     *                 if the parameter specification type is not assignable
     *                 from {@link PBES2ParameterSpec}.
     */
    public AlgorithmParameterSpec getParameterSpec(Class paramSpec)
	    throws InvalidParameterSpecException {

	if (!paramSpec.isAssignableFrom(PBES2ParameterSpec.class)) {
	    throw new InvalidParameterSpecException("unsupported type");
	}
	return new PBES2ParameterSpec(keyDerivationFunction, encryptionScheme);
    }

    /**
     * @return a human readable form of the parameters
     */
    public String toString() {

	return "key derivation function OID: "
		+ keyDerivationFunction.getAlgorithmOID().toString() + "\n"
		+ "encryption scheme OID       :       "
		+ encryptionScheme.getAlgorithmOID().toString();
    }

}
