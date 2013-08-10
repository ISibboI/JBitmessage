/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.rijndael;

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
 * This class is used as an opaque representation of Rijndael parameters.
 * ASN.1/DER encoding and decoding are supported.
 * 
 * @see AlgorithmParameterSpec
 * @author Katja Rauch
 */
public class RijndaelParameters extends AlgorithmParameters {

    // the block size in bits
    private int blockSize;

    // the initialization vector
    private byte[] iv;

    /**
     * Initialize this parameters object using the given parameter
     * specification. The parameter specification has to be an instance of
     * {@link RijndaelParameterSpec}.
     * 
     * @param params
     *                the parameter specification
     * @throws InvalidParameterSpecException
     *                 if the parameter specification is <tt>null</tt> or of
     *                 an unsupported type.
     */
    public void init(AlgorithmParameterSpec params)
	    throws InvalidParameterSpecException {
	if ((params == null) || !(params instanceof RijndaelParameterSpec)) {
	    throw new InvalidParameterSpecException("unsupported type");
	}

	blockSize = ((RijndaelParameterSpec) params).getBlockSize();
	iv = ((RijndaelParameterSpec) params).getIV();
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

	// decode block size
	blockSize = ASN1Tools.getFlexiBigInt((ASN1Integer) params.get(0))
		.intValue();

	// decode IV
	ASN1Type ivType = ((ASN1Choice) params.get(1)).getInnerType();
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
     * RijndaelParameters ::= SEQUENCE {
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
	ASN1Sequence params = new ASN1Sequence(2);

	// encode block size
	params.add(new ASN1Integer(blockSize));

	// encode IV
	if (iv == null) {
	    // encode as NULL
	    params.add(new ASN1Null());
	} else {
	    // encode as OCTET STRING
	    params.add(new ASN1OctetString(iv));
	}

	// return encoded parameters
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
     * parameters should be returned. Currently, only
     * {@link RijndaelParameterSpec} is supported.
     * 
     * @param paramSpec
     *                the the specification class in which the parameters should
     *                be returned
     * @return the parameter specification
     * @throws InvalidParameterSpecException
     *                 if the requested parameter is not
     *                 {@link RijndaelParameterSpec}.
     */
    public AlgorithmParameterSpec getParameterSpec(Class paramSpec)
	    throws InvalidParameterSpecException {

	if (!(RijndaelParameterSpec.class.isAssignableFrom(paramSpec))) {
	    throw new InvalidParameterSpecException("unsupported type");
	}

	if (iv == null) {
	    return new RijndaelParameterSpec(blockSize);
	}
	return new RijndaelParameterSpec(blockSize, new ModeParameterSpec(iv));
    }

    /**
     * @return a formatted string describing the parameters
     */
    public String toString() {
	StringBuffer buf = new StringBuffer();
	buf.append("RijndaelParameters (block size " + blockSize + ")");
	buf.append("(IV " + ByteUtils.toHexString(iv) + ")");

	return buf.toString();
    }
}
