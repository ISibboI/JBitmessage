/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */
package de.flexiprovider.core.kdf;

import java.io.IOException;

import codec.asn1.ASN1Choice;
import codec.asn1.ASN1Exception;
import codec.asn1.ASN1Integer;
import codec.asn1.ASN1Null;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1OctetString;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1Type;
import de.flexiprovider.api.exceptions.InvalidParameterSpecException;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.api.parameters.AlgorithmParameters;
import de.flexiprovider.common.util.ASN1Tools;
import de.flexiprovider.common.util.ByteUtils;
import de.flexiprovider.pki.AlgorithmIdentifier;

/**
 * This class represents parameters for the default key derivation function (OID
 * 1.2.840.113549.2.7) for the passphrase based encryption.
 * 
 * @author Thomas Wahrenbruch
 * @author Martin Döring
 */
public class PBKDF2Parameters extends AlgorithmParameters {

    /**
     * The OID of PBKDF2.
     */
    public static final String OID = PBKDF2.OID;

    // the salt
    private byte[] salt;

    // the iteration count.
    private int iterationCount = 1000;

    // the key size
    private int keySize;

    /**
     * Inner class providing the PBKDF2 ASN.1 parameters structure.
     * <p>
     * The ASN.1 parameters structure is defined as follows:
     * 
     * <pre>
     * PBKDF2-params ::= SEQUENCE {
     *   salt CHOICE {
     *     specified   OCTET STRING,
     *     otherSource AlgorithmIdentifier {{PBKDF2-SaltSources}}
     *   },
     *   iterationCount INTEGER,
     *   keySize        INTEGER OPTIONAL,
     *   prf            AlgorithmIdentifier {{PBKDF2-PRFs}} DEFAULT algid-hmacWithSHA1
     * }
     * </pre>
     * 
     * @author Thomas Wahrenbruch
     * @author Martin Döring
     */
    private static class PBKDF2ASN1Params extends ASN1Sequence {

	// the salt
	private ASN1Choice salt;

	// the iteration count
	private ASN1Integer iterationCount;

	// the key size
	private ASN1Integer keySize;

	// the algorithm identifier of the PRF
	private AlgorithmIdentifier prf;

	/**
	 * Construct the ASN.1 structure (used for decoding).
	 */
	public PBKDF2ASN1Params() {
	    super(4);
	    salt = new ASN1Choice();
	    salt.addType(new ASN1OctetString());
	    salt.addType(new AlgorithmIdentifier());
	    iterationCount = new ASN1Integer();
	    keySize = new ASN1Integer();
	    keySize.setOptional(true);
	    prf = new AlgorithmIdentifier();
	    prf.setOptional(true);

	    add(salt);
	    add(iterationCount);
	    add(keySize);
	    add(prf);
	}

	/**
	 * Construct an ASN.1 structure with the given parameters (used for
	 * encoding).
	 * 
	 * @param salt
	 *                the salt
	 * @param iterationCount
	 *                the iteration count
	 * @param keySize
	 *                the length of the key
	 */
	public PBKDF2ASN1Params(byte[] salt, int iterationCount, int keySize) {
	    super(4);
	    this.salt = new ASN1Choice();
	    this.salt.setInnerType(new ASN1OctetString(salt));
	    this.iterationCount = new ASN1Integer(iterationCount);
	    this.keySize = new ASN1Integer(keySize);

	    try {
		prf = new AlgorithmIdentifier(new ASN1ObjectIdentifier(
			PBKDF2ParameterSpec.DEFAULT_PRF_OID), new ASN1Null());
	    } catch (ASN1Exception ae) {
		throw new RuntimeException("internal error");
	    }

	    add(this.salt);
	    add(this.iterationCount);
	    add(this.keySize);
	    add(prf);
	}

	/**
	 * Returns the iteration count.
	 * <p>
	 * 
	 * @return the iterationCount
	 */
	public int getIterationCount() {
	    return ASN1Tools.getFlexiBigInt(iterationCount).intValue();
	}

	/**
	 * Returns the length of the key.
	 * <p>
	 * 
	 * @return the keySize.
	 */
	public int getKeyLength() {
	    if (keySize.isOptional()) {
		return 0;
	    }
	    return ASN1Tools.getFlexiBigInt(keySize).intValue();
	}

	/**
	 * Returns the AlgorithmIdentifier of the pseudo random function.
	 * <p>
	 * 
	 * @return the AlgorithmIdentifier of the pseudo random function
	 */
	public AlgorithmIdentifier getPRFAlgorithmIdentifier() {
	    if (prf.isOptional()) {
		// the DEFAULT - hmacWithSHA1
		try {
		    AlgorithmIdentifier hmacWithSHA1 = new AlgorithmIdentifier(
			    new ASN1ObjectIdentifier("1.2.840.113549.2.7"),
			    new ASN1Null());
		    return hmacWithSHA1;
		} catch (ASN1Exception ae) {
		    ae.printStackTrace();
		}
		// shouldn't happen !
		return null;
	    }
	    return prf;
	}

	/**
	 * Returns the salt.
	 * <p>
	 * 
	 * @return the salt
	 */
	public byte[] getSalt() {

	    // exception if there is an AlgortihmIdentifier....

	    ASN1Type inner = salt.getInnerType();
	    if (inner != null) {
		if (inner instanceof ASN1OctetString) {
		    ASN1OctetString os = (ASN1OctetString) inner;
		    return os.getByteArray();
		}
	    }
	    return null;
	}
    }

    /**
     * Initialize the parameters with the given parameter specification.
     * Currently, only {@link PBKDF2ParameterSpec} is supported as specification
     * type.
     * 
     * @param params
     *                the parameter specification
     * @throws InvalidParameterSpecException
     *                 if the parameter specification is not an instance of
     *                 {@link PBKDF2ParameterSpec}.
     */
    public void init(AlgorithmParameterSpec params)
	    throws InvalidParameterSpecException {
	if (!(params instanceof PBKDF2ParameterSpec)) {
	    throw new InvalidParameterSpecException("unsupported type");
	}
	PBKDF2ParameterSpec pbkdf2Params = (PBKDF2ParameterSpec) params;

	salt = pbkdf2Params.getSalt();
	iterationCount = pbkdf2Params.getIterationCount();
	keySize = pbkdf2Params.getKeySize();
    }

    /**
     * Import the specified parameters and decode them according to the primary
     * decoding format (ASN.1) for parameters.
     * 
     * @param encParams
     *                the encoded parameters
     * @throws IOException
     *                 on decoding errors.
     */
    public void init(byte[] encParams) throws IOException {
	PBKDF2ASN1Params asn1params;
	try {
	    asn1params = new PBKDF2ASN1Params();
	    ASN1Tools.derDecode(encParams, asn1params);
	} catch (ASN1Exception ae) {
	    throw new IOException("ASN1Exception: " + ae.getMessage());
	}

	salt = asn1params.getSalt();
	iterationCount = asn1params.getIterationCount();
	keySize = asn1params.getKeyLength();
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
	PBKDF2ASN1Params asn1pbeParams = new PBKDF2ASN1Params(salt,
		iterationCount, keySize);

	try {
	    return ASN1Tools.derEncode(asn1pbeParams);
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
	if ((format != null) && !format.equals("ASN.1")) {
	    throw new IOException("unsupported format");
	}
	return getEncoded();
    }

    /**
     * Return a transparent specification of the parameters. Currently, only
     * {@link PBKDF2ParameterSpec} is supported as specification type.
     * 
     * @param paramSpec
     *                the desired parameter specification type
     * @return the parameter specification
     * @throws InvalidParameterSpecException
     *                 if the parameter specification type is not assignable
     *                 from {@link PBKDF2ParameterSpec}.
     */
    public AlgorithmParameterSpec getParameterSpec(Class paramSpec)
	    throws InvalidParameterSpecException {

	if (!paramSpec.isAssignableFrom(PBKDF2ParameterSpec.class)) {
	    throw new InvalidParameterSpecException("unsupported type");
	}
	return new PBKDF2ParameterSpec(salt, iterationCount, keySize);
    }

    /**
     * @return a human readable form of the parameters
     */
    public String toString() {
	String result = "salt             : " + ByteUtils.toHexString(salt);
	result += "\niteration count: " + iterationCount;
	result += "\nkey size       : " + keySize;
	result += "\nprf OID        : " + PBKDF2ParameterSpec.DEFAULT_PRF_OID;
	return result;
    }

}
