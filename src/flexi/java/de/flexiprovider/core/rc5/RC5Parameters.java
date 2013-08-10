/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */
package de.flexiprovider.core.rc5;

import java.io.IOException;

import codec.asn1.ASN1Choice;
import codec.asn1.ASN1Exception;
import codec.asn1.ASN1Integer;
import codec.asn1.ASN1Null;
import codec.asn1.ASN1OctetString;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1Type;
import de.flexiprovider.api.exceptions.InvalidParameterSpecException;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.api.parameters.AlgorithmParameters;
import de.flexiprovider.common.mode.ModeParameterSpec;
import de.flexiprovider.common.util.ASN1Tools;
import de.flexiprovider.common.util.ByteUtils;

/**
 * This class is used as an opaque representation of RC5 parameters. ASN.1/DER
 * encoding and decoding are supported.
 * 
 * @see AlgorithmParameterSpec
 * @author Oliver Seiler
 */
public class RC5Parameters extends AlgorithmParameters {

    private int version;

    private int rounds;

    private int blockSize;

    private byte[] iv;

    /**
     * Initialize this parameters object using the given parameter
     * specification. The parameter specification has to be an instance of
     * {@link RC5ParameterSpec}.
     * 
     * @param params
     *                the parameter specification
     * @throws InvalidParameterSpecException
     *                 if the parameter specification is <tt>null</tt> or of
     *                 an unsupported type.
     */
    public void init(AlgorithmParameterSpec params)
	    throws InvalidParameterSpecException {

	if ((params == null) || !(params instanceof RC5ParameterSpec)) {
	    throw new InvalidParameterSpecException("unsupported type");
	}
	RC5ParameterSpec rc5Params = (RC5ParameterSpec) params;

	version = rc5Params.getVersion();
	rounds = rc5Params.getNumRounds();
	blockSize = rc5Params.getWordSize();
	iv = rc5Params.getIV();
    }

    /**
     * Import the specified parameters and decode them according to the primary
     * decoding format (ASN.1).
     * 
     * @param encParams
     *                the encoded parameters.
     * @throws IOException
     *                 on decoding errors
     */
    public void init(byte[] encParams) throws IOException {
	// build the parameters structure
	ASN1Sequence params = new ASN1Sequence(2);
	params.add(new ASN1Integer());
	params.add(new ASN1Integer());
	params.add(new ASN1Integer());
	ASN1Choice ivChoice = new ASN1Choice();
	// either NULL
	ivChoice.addType(new ASN1Null());
	// or an OCTET STRING
	ivChoice.addType(new ASN1OctetString());
	params.add(ivChoice);

	// decode parameters
	try {
	    ASN1Tools.derDecode(encParams, params);
	} catch (ASN1Exception e) {
	    throw new IOException("bad encoding");
	}

	// decode version
	version = ASN1Tools.getFlexiBigInt((ASN1Integer) params.get(0))
		.intValue();

	// decode number of rounds
	rounds = ASN1Tools.getFlexiBigInt((ASN1Integer) params.get(1))
		.intValue();

	// decode block size
	blockSize = ASN1Tools.getFlexiBigInt((ASN1Integer) params.get(2))
		.intValue();

	// decode IV
	ASN1Type ivType = ((ASN1Choice) params.get(3)).getInnerType();
	if (ivType instanceof ASN1Null) {
	    iv = null;
	} else {
	    iv = ((ASN1OctetString) ivType).getByteArray();
	}
    }

    /**
     * Import the specified parameters and decode them according to the
     * specified decoding format. Currently, only the primary decoding format
     * (ASN.1) is supported.
     * 
     * @param encParams
     *                the encoded parameters
     * @param format
     *                the name of the decoding format
     * @throws IOException
     *                 if format is not equal to "ASN.1" or on decoding errors.
     */
    public void init(byte[] encParams, String format) throws IOException {
	if (!format.equals("ASN.1")) {
	    throw new IOException("unsupported format");
	}
	init(encParams);
    }

    /**
     * Return the parameters encoded in the primary encoding format (ASN.1).
     * <p>
     * The ASN.1 definition of the parameters structure is:
     * 
     * <pre>
     * RC5Parameters ::= SEQUENCE {
     *   version    INTEGER,
     *   rounds     INTEGER,
     *   blockSize  INTEGER,
     *   iv         CHOICE {
     *     NULL,
     *     OCTET STRING
     *   }
     * }
     * </pre>
     * 
     * @return the encoded parameters
     */
    public byte[] getEncoded() {
	ASN1Sequence params = new ASN1Sequence(4);

	// encode version
	params.add(new ASN1Integer(version));

	// encode number of rounds
	params.add(new ASN1Integer(rounds));

	// encode word size
	params.add(new ASN1Integer(blockSize));

	// encode IV
	if (iv == null) {
	    // encode as NULL
	    params.add(new ASN1Null());
	} else {
	    // encode as OCTET STRING
	    params.add(new ASN1OctetString(iv));
	}

	return ASN1Tools.derEncode(params);
    }

    /**
     * Return the parameters encoded in the specified encoding format.
     * Currently, only the primary encoding format (ASN.1) is supported.
     * 
     * @param format
     *                the name of the encoding format
     * @return the encoded parameters
     * @throws IOException
     *                 if format is not equal to "ASN.1" or on decoding errors.
     */
    public byte[] getEncoded(String format) throws IOException {
	if (!format.equals("ASN.1")) {
	    throw new IOException("unsupported format");
	}
	return getEncoded();
    }

    /**
     * Return a transparent specification of this parameters object.
     * <tt>paramSpec</tt> identifies the specification class in which the
     * parameters should be returned. Currently, only {@link RC5ParameterSpec}
     * is supported.
     * 
     * @param paramSpec
     *                the the specification class in which the parameters should
     *                be returned
     * @return the parameter specification
     * @throws InvalidParameterSpecException
     *                 if the requested parameter is not
     *                 {@link RC5ParameterSpec}.
     */
    public AlgorithmParameterSpec getParameterSpec(Class paramSpec)
	    throws InvalidParameterSpecException {
	if (!paramSpec.isAssignableFrom(RC5ParameterSpec.class)) {
	    throw new InvalidParameterSpecException("unsupported type");
	}

	if (iv == null) {
	    return new RC5ParameterSpec(rounds, blockSize);
	}
	return new RC5ParameterSpec(rounds, blockSize,
		new ModeParameterSpec(iv));
    }

    /**
     * @return a human readable form of the parameters
     */
    public String toString() {
	String result = "RC5 Parameters:\n";

	result += "  version   : " + version + "\n";
	result += "  rounds    : " + rounds + "\n";
	result += "  block size: " + blockSize + " bits\n";
	result += "  IV        : ";
	if (iv == null) {
	    result += "null\n";
	} else {
	    result += ByteUtils.toHexString(iv) + "\n";
	}

	return result;
    }

}
