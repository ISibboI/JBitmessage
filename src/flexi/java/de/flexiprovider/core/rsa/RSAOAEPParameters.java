package de.flexiprovider.core.rsa;

import java.io.IOException;

import codec.asn1.ASN1Exception;
import codec.asn1.ASN1Null;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1OctetString;
import codec.asn1.ASN1Sequence;
import de.flexiprovider.api.exceptions.InvalidParameterSpecException;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.api.parameters.AlgorithmParameters;
import de.flexiprovider.common.util.ASN1Tools;
import de.flexiprovider.pki.AlgorithmIdentifier;

/**
 * This class provides ASN.1 encoding and decoding of parameters for RSA-OAEP
 * (specified by {@link RSAOAEPParameterSpec}).
 * 
 * @author Martin Döring
 */
public class RSAOAEPParameters extends AlgorithmParameters {

    // the OID of the hash function
    private String md;

    /**
     * Initialize the parameters with the given parameter specification.
     * Currently, only parameter specifications of type
     * {@link RSAOAEPParameterSpec} are supported.
     * 
     * @param paramSpec
     *                the parameter specification
     * @throws InvalidParameterSpecException
     *                 if the parameter specification is <tt>null</tt> or nor
     *                 an instance of {@link RSAOAEPParameterSpec}.
     */
    public void init(AlgorithmParameterSpec paramSpec)
	    throws InvalidParameterSpecException {

	if ((paramSpec == null) || !(paramSpec instanceof RSAOAEPParameterSpec)) {
	    throw new InvalidParameterSpecException("unsupported type");
	}

	md = ((RSAOAEPParameterSpec) paramSpec).getMD();
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
	asn1Params.add(new AlgorithmIdentifier());

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
	if (!mgf.equals(RSAOAEPParameterSpec.DEFAULT_MGF)) {
	    throw new IOException("unsupported parameters");
	}

	// decode PSource algorithm OID
	String pSource = ((AlgorithmIdentifier) asn1Params.get(2))
		.getAlgorithmOID().toString();
	// check whether PSource algorithm is supported
	if (!pSource.equals(RSAOAEPParameterSpec.DEFAULT_PSOURCE)) {
	    throw new IOException("unsupported parameters");
	}

	// decode hash function OID
	md = ((AlgorithmIdentifier) asn1Params.get(0)).getAlgorithmOID()
		.toString();
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
     * RSAES-OAEP-params ::= SEQUENCE {
     *   md       AlgorithmIdentifier,
     *   mgf      AlgorithmIdentifier,
     *   pSource  AlgorithmIdentifier,
     * }
     * </pre>
     * 
     * @return the encoded parameters
     * @throws IOException
     *                 on encoding errors.
     */
    public byte[] getEncoded() throws IOException {
	ASN1Sequence asn1Params = new ASN1Sequence(3);
	AlgorithmIdentifier mdIdentifier, mgfIdentifier, pSourceIdentifier;
	try {
	    // encode hash function OID
	    mdIdentifier = new AlgorithmIdentifier(
		    new ASN1ObjectIdentifier(md), new ASN1Null());
	    // encode mask generation function OID
	    mgfIdentifier = new AlgorithmIdentifier(new ASN1ObjectIdentifier(
		    RSAOAEPParameterSpec.DEFAULT_MGF), mdIdentifier);
	    // encode PSource algorithm OID
	    pSourceIdentifier = new AlgorithmIdentifier(
		    new ASN1ObjectIdentifier(
			    RSAOAEPParameterSpec.DEFAULT_PSOURCE),
		    new ASN1OctetString());
	} catch (ASN1Exception e) {
	    throw new IOException("ASN1Exception: " + e.getMessage());
	}

	asn1Params.add(mdIdentifier);
	asn1Params.add(mgfIdentifier);
	asn1Params.add(pSourceIdentifier);

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
     * {@link RSAOAEPParameterSpec} is supported as parameter specification
     * type.
     * 
     * @param paramSpec
     *                the desired parameter specification type
     * @return the parameter specification
     * @throws InvalidParameterSpecException
     *                 if the parameter specification type is <tt>null</tt> or
     *                 not assignable from {@link RSAOAEPParameterSpec}.
     */
    public AlgorithmParameterSpec getParameterSpec(Class paramSpec)
	    throws InvalidParameterSpecException {
	if ((paramSpec == null)
		|| !(paramSpec.isAssignableFrom(RSAOAEPParameterSpec.class))) {
	    throw new InvalidParameterSpecException("unsupported type");
	}
	return new RSAOAEPParameterSpec(md);
    }

    /**
     * @return a human readable form of the parameters
     */
    public String toString() {
	String result = "RSA OAEP parameters:\n";
	result += "MD OID     : " + md + "\n";
	result += "MGF OID    : " + RSAOAEPParameterSpec.DEFAULT_MGF + "\n";
	result += "PSource OID: " + RSAOAEPParameterSpec.DEFAULT_PSOURCE + "\n";
	return result;
    }

}
