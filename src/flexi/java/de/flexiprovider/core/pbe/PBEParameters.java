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
import codec.asn1.ASN1Integer;
import codec.asn1.ASN1OctetString;
import codec.asn1.ASN1Sequence;
import de.flexiprovider.api.exceptions.InvalidParameterSpecException;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.util.ASN1Tools;
import de.flexiprovider.common.util.ByteUtils;

/**
 * This class represents parameters for passphrase based encryption.
 * 
 * @author Thomas Wahrenbruch
 */
public class PBEParameters extends
	de.flexiprovider.core.pbe.interfaces.PBEParameters {

    /**
     * The salt
     */
    private byte[] salt;

    /**
     * The iteration count
     */
    private int iterationCount;

    /**
     * Inner class providing the PBES1 ASN.1 parameters structure.
     * <p>
     * The ASN.1 parameters structure is defined as follows:
     * 
     * <pre>
     * PBEParameters ::= SEQUENCE {
     * 	 salt             OCTET STRING,
     *   iteration count  INTEGER
     * }
     * </pre>
     * 
     * @author Thomas Wahrenbruch
     * @author Martin Döring
     */
    private static class PBES1ASN1Parameters extends ASN1Sequence {

	// the salt
	private ASN1OctetString salt;

	// the iteration count
	private ASN1Integer iterationCount;

	/**
	 * Construct the ASN.1 structure (used for decoding).
	 */
	public PBES1ASN1Parameters() {
	    super(2);
	    salt = new ASN1OctetString();
	    iterationCount = new ASN1Integer();

	    add(salt);
	    add(iterationCount);
	}

	/**
	 * Construct an ASN.1 structure with the given parameters (used for
	 * encoding).
	 * 
	 * @param salt
	 *                the salt
	 * @param iterationCount
	 *                the iteration count
	 */
	public PBES1ASN1Parameters(byte[] salt, int iterationCount) {
	    super(2);
	    this.salt = new ASN1OctetString(salt);
	    this.iterationCount = new ASN1Integer(iterationCount);

	    add(this.salt);
	    add(this.iterationCount);
	}

	/**
	 * @return the iteration count
	 */
	public int getIterationCount() {
	    return ASN1Tools.getFlexiBigInt(iterationCount).intValue();
	}

	/**
	 * @return the salt
	 */
	public byte[] getSalt() {
	    return salt.getByteArray();
	}
    }

    /**
     * Initialize this parameters object using the specified parameters.
     * Currently, only {@link PBEParameterSpec} is supported as specification
     * type.
     * 
     * @param paramSpec
     *                the parameter specification
     * @throws InvalidParameterSpecException
     *                 if the parameter specification is not an instance of
     *                 {@link PBEParameterSpec}.
     */
    public void init(AlgorithmParameterSpec paramSpec)
	    throws InvalidParameterSpecException {
	if (!(paramSpec instanceof PBEParameterSpec)) {
	    throw new InvalidParameterSpecException("unsupported type");
	}
	PBEParameterSpec pbeParamSpec = (PBEParameterSpec) paramSpec;

	salt = pbeParamSpec.getSalt();
	iterationCount = pbeParamSpec.getIterationCount();
    }

    /**
     * Import the specified parameters and decodes them according to the primary
     * decoding format (ASN.1) for parameters.
     * 
     * @param enc
     *                the encoded parameters
     * @throws IOException
     *                 on decoding errors.
     */
    public void init(byte[] enc) throws IOException {
	try {
	    PBES1ASN1Parameters asn1params = new PBES1ASN1Parameters();
	    ASN1Tools.derDecode(enc, asn1params);

	    salt = asn1params.getSalt();
	    iterationCount = asn1params.getIterationCount();
	} catch (ASN1Exception ae) {
	    throw new IOException("ASN1Exception: " + ae.getMessage());
	}
    }

    /**
     * Import the specified parameters and decodes them according to the
     * specified decoding format. If <tt>format</tt> is null, the primary
     * decoding format for parameters (ASN.1) is used. Currently, only the
     * default decoding format is supported.
     * 
     * @param enc
     *                the encoded parameters
     * @param format
     *                the decoding format
     * @throws IOException
     *                 on decoding errors.
     */
    public void init(byte[] enc, String format) throws IOException {
	if (format != null) {
	    throw new IOException("Decoding format '" + format
		    + "' not supported.");
	}

	init(enc);
    }

    /**
     * Return the parameters in their primary encoding format. The primary
     * encoding format for parameters is ASN.1.
     * 
     * @return the ASN.1 encoded parameters
     * @throws IOException
     *                 on encoding errors.
     */
    public byte[] getEncoded() throws IOException {
	PBES1ASN1Parameters asn1pbeParams = new PBES1ASN1Parameters(salt,
		iterationCount);

	try {
	    return ASN1Tools.derEncode(asn1pbeParams);
	} catch (RuntimeException re) {
	    throw new IOException(re.getMessage());
	}
    }

    /**
     * Return the parameters in the specified encoding format. If
     * <tt>format</tt> is null, the primary encoding format for parameters
     * (ASN.1) is used. Currently, only the default encoding format is
     * supported.
     * 
     * @param format
     *                the encoding format
     * @return the ASN.1 encoded parameters
     * @throws IOException
     *                 on encoding errors.
     */
    public byte[] getEncoded(String format) throws IOException {
	if (format != null) {
	    throw new IOException("Encoding format '" + format
		    + "' not supported.");
	}

	return getEncoded();
    }

    /**
     * Return a transparent specification of this parameters object. Currently,
     * only {@link PBEParameterSpec}is supported as specification type.
     * 
     * @param paramSpec
     *                the the specification class in which the parameters should
     *                be returned
     * @return the parameter specification
     * @throws InvalidParameterSpecException
     *                 if the parameter specification type is not assignable
     *                 from {@link PBEParameterSpec}.
     */
    public AlgorithmParameterSpec getParameterSpec(Class paramSpec)
	    throws InvalidParameterSpecException {
	if (!paramSpec.isAssignableFrom(PBEParameterSpec.class)) {
	    throw new InvalidParameterSpecException("unsupported type");
	}
	return new PBEParameterSpec(salt, iterationCount);
    }

    /**
     * @return a human readable form of the parameters
     */
    public String toString() {
	String result = "";
	result += "Salt           : " + ByteUtils.toHexString(salt);
	result += "iteration count: " + iterationCount;
	return result;
    }

}
