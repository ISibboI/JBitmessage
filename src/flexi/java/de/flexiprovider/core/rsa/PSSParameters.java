package de.flexiprovider.core.rsa;

import java.io.IOException;

import codec.asn1.ASN1Exception;
import codec.asn1.ASN1Integer;
import codec.asn1.ASN1Null;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1Sequence;
import de.flexiprovider.api.exceptions.InvalidParameterSpecException;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.api.parameters.AlgorithmParameters;
import de.flexiprovider.common.util.ASN1Tools;
import de.flexiprovider.pki.AlgorithmIdentifier;

/**
 * This class provides ASN.1 encoding and decoding of parameters for the
 * RSASSA-PSS signature algorithm (specified by {@link PSSParameterSpec}).
 * 
 * @author Martin Döring
 */
public class PSSParameters extends AlgorithmParameters {

    // the OID of the hash function
    private String md;

    // the salt length
    private int saltLength;

    /**
     * Initialize the parameters with the given parameter specification.
     * Currently, only parameter specifications of type {@link PSSParameterSpec}
     * are supported.
     * 
     * @param paramSpec
     *                the parameter specification
     * @throws InvalidParameterSpecException
     *                 if the parameter specification is <tt>null</tt> or nor
     *                 an instance of {@link PSSParameterSpec}.
     */
    public void init(AlgorithmParameterSpec paramSpec)
	    throws InvalidParameterSpecException {

	if ((paramSpec == null) || !(paramSpec instanceof PSSParameterSpec)) {
	    throw new InvalidParameterSpecException("unsupported type");
	}
	PSSParameterSpec pssParams = (PSSParameterSpec) paramSpec;

	md = pssParams.getMD();
	saltLength = pssParams.getSaltLength();
    }

    /**
     * Import the given encoded parameters and decode them according to the
     * primary encoding format (ASN.1).
     * 
     * @param encParams
     *                the encoded parameters
     * @throws IOException
     *                 on decoding errors.
     */
    public void init(byte[] encParams) throws IOException {
	// build the ASN.1 parameters structure
	ASN1Sequence asn1Params = new ASN1Sequence(3);
	asn1Params.add(new AlgorithmIdentifier());
	asn1Params.add(new AlgorithmIdentifier());
	asn1Params.add(new ASN1Integer());
	asn1Params.add(new ASN1Integer());

	// decode the parameters
	try {
	    ASN1Tools.derDecode(encParams, asn1Params);
	} catch (ASN1Exception e) {
	    throw new IOException("ASN1Exception: " + e.getMessage());
	}

	// decode mask generation function OID
	String mgf = ((AlgorithmIdentifier) asn1Params.get(1))
		.getAlgorithmOID().toString();
	// check whether mask generation function is supported
	if (!mgf.equals(PSSParameterSpec.DEFAULT_MGF)) {
	    throw new IOException("unsupported parameters");
	}

	// decode trailerField
	int trailerField = ASN1Tools.getFlexiBigInt(
		(ASN1Integer) asn1Params.get(3)).intValue();
	// check whether trailer field is supported
	if (trailerField != PSSParameterSpec.DEFAULT_TRAILER_FIELD) {
	    throw new IOException("unsupported parameters");
	}

	// decode hash function OID
	md = ((AlgorithmIdentifier) asn1Params.get(0)).getAlgorithmOID()
		.toString();

	// decode salt length
	saltLength = ASN1Tools.getFlexiBigInt((ASN1Integer) asn1Params.get(2))
		.intValue();
    }

    /**
     * Import the given encoded parameters and decode them according to the
     * specified encoding format. Currently, only the primary encoding format
     * (ASN.1) is supported.
     * 
     * @param encParams
     *                the encoded parameters
     * @param format
     *                the encoding format
     * @throws IOException
     *                 on decoding errors or if the encoding format is
     *                 <tt>null</tt> or not equals to "ASN.1".
     */
    public void init(byte[] encParams, String format) throws IOException {
	if ((format == null) || !format.equals("ASN.1")) {
	    throw new IOException("unsupported format");
	}
	init(encParams);
    }

    /**
     * Encode the parameters according to the primary encoding format (ASN.1).
     * <p>
     * The ASN.1 definition of the parameters structure is
     * 
     * <pre>
     * RSASSA-PSS-params ::= SEQUENCE {
     *   md            AlgorithmIdentifier,
     *   mgf           AlgorithmIdentifier,
     *   saltLength    INTEGER
     *   trailerField  INTEGER(1)
     * }
     * </pre>
     * 
     * @return the encoded parameters
     * @throws IOException
     *                 on encoding errors.
     */
    public byte[] getEncoded() throws IOException {
	ASN1Sequence asn1Params = new ASN1Sequence(3);
	AlgorithmIdentifier mdIdentifier, mgfIdentifier;
	try {
	    // encode hash function OID
	    mdIdentifier = new AlgorithmIdentifier(
		    new ASN1ObjectIdentifier(md), new ASN1Null());
	    asn1Params.add(mdIdentifier);

	    // encode mask generation function OID
	    mgfIdentifier = new AlgorithmIdentifier(new ASN1ObjectIdentifier(
		    PSSParameterSpec.DEFAULT_MGF), mdIdentifier);
	    asn1Params.add(mgfIdentifier);
	} catch (ASN1Exception e) {
	    throw new IOException("ASN1Exception: " + e.getMessage());
	}

	// encode salt length
	asn1Params.add(new ASN1Integer(saltLength));

	// encode trailer field
	asn1Params.add(new ASN1Integer(PSSParameterSpec.DEFAULT_TRAILER_FIELD));

	return ASN1Tools.derEncode(asn1Params);
    }

    /**
     * Encode the parameters according to the specified encoding format.
     * Currently, only the primary encoding format (ASN.1) is supported.
     * 
     * @param format
     *                the encoding format
     * @return the encoded parameters
     * @throws IOException
     *                 on encoding errors or if the encoding format is
     *                 <tt>null</tt> or not equals to "ASN.1".
     */
    public byte[] getEncoded(String format) throws IOException {
	if ((format == null) || !format.equals("ASN.1")) {
	    throw new IOException("unsupported format");
	}
	return getEncoded();
    }

    /**
     * Return a transparent specification of the parameters. Currently, only
     * {@link PSSParameterSpec} is supported as parameter specification type.
     * 
     * @param paramSpec
     *                the desired parameter specification type
     * @return the parameter specification
     * @throws InvalidParameterSpecException
     *                 if the parameter specification type is <tt>null</tt> or
     *                 not assignable from {@link PSSParameterSpec}.
     */
    public AlgorithmParameterSpec getParameterSpec(Class paramSpec)
	    throws InvalidParameterSpecException {
	if ((paramSpec == null)
		|| !(paramSpec.isAssignableFrom(PSSParameterSpec.class))) {
	    throw new InvalidParameterSpecException("unsupported type");
	}
	return new PSSParameterSpec(md, saltLength);
    }

    /**
     * @return a human readable form of the parameters
     */
    public String toString() {
	String result = "PSS parameters:\n";
	result += "MD OID       : " + md + "\n";
	result += "MGF OID      : " + PSSParameterSpec.DEFAULT_MGF + "\n";
	result += "salt length  : " + saltLength + "\n";
	result += "trailer field: " + PSSParameterSpec.DEFAULT_TRAILER_FIELD
		+ "\n";
	return result;
    }

}
