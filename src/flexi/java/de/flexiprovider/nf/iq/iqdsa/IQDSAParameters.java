package de.flexiprovider.nf.iq.iqdsa;

import java.io.IOException;

import codec.asn1.ASN1Exception;
import codec.asn1.ASN1Integer;
import codec.asn1.ASN1OctetString;
import codec.asn1.ASN1Sequence;
import de.flexiprovider.api.exceptions.InvalidParameterSpecException;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.api.parameters.AlgorithmParameters;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.math.quadraticfields.IQEncodingException;
import de.flexiprovider.common.math.quadraticfields.QuadraticIdeal;
import de.flexiprovider.common.util.ASN1Tools;

/**
 * This class is used as an opaque representation of cryptographic parameters.
 * <p>
 * A transparent parameter specification is obtained from an
 * <tt>AlgorithmParameters</tt> object via a call to <tt>getParameterSpec</tt>,
 * and a byte encoding of the parameters is obtained via a call to
 * <tt>getEncoded</tt>.
 * 
 * @author Ralf-P. Weinmann
 */
public class IQDSAParameters extends AlgorithmParameters {

    private FlexiBigInt discriminant;

    private QuadraticIdeal gamma;

    /**
     * Inner class specifying the IQDSA ASN.1 parameters structure.
     */
    private static class IQDSAASN1Parameters extends ASN1Sequence {

	/**
	 * Version always is 1.
	 */
	private static final ASN1Integer version = new ASN1Integer(1);

	private ASN1Integer discriminant;

	private ASN1OctetString gamma;

	/**
	 * Default constructor, used for decoding.
	 */
	public IQDSAASN1Parameters() {
	    super(3);
	    discriminant = new ASN1Integer();
	    gamma = new ASN1OctetString();
	    add(version);
	    add(discriminant);
	    add(gamma);
	}

	/**
	 * Construct new IQDSA ASN.1 parameters from the given discriminant and
	 * generator of the class group.
	 * 
	 * @param discriminant
	 *                the discriminant of the class group
	 * @param gamma
	 *                the generator of the class group
	 */
	public IQDSAASN1Parameters(FlexiBigInt discriminant,
		QuadraticIdeal gamma) {
	    super(3);
	    this.discriminant = ASN1Tools.createInteger(discriminant);
	    // no compression
	    this.gamma = new ASN1OctetString(gamma.idealToOctets(discriminant,
		    false));
	    add(version);
	    add(this.discriminant);
	    add(this.gamma);
	}

	/**
	 * @return the discriminant of the class group
	 */
	public FlexiBigInt getDiscriminant() {
	    return ASN1Tools.getFlexiBigInt(discriminant);
	}

	/**
	 * @return the generator of the class group
	 * @throws IQEncodingException
	 *                 if the generator of the class group cannot be
	 *                 encoded.
	 */
	public QuadraticIdeal getGamma() throws IQEncodingException {
	    return QuadraticIdeal.octetsToIdeal(getDiscriminant(), gamma
		    .getByteArray());
	}

    }

    /**
     * Initialize the parameters object with the given parameter specification
     * (supposed to be an instance of {@link IQDSAParameterSpec}).
     * 
     * @param params
     *                the parameter specification
     * @throws InvalidParameterSpecException
     *                 if the parameter specification is not an instance of
     *                 {@link IQDSAParameterSpec}.
     */
    public void init(AlgorithmParameterSpec params)
	    throws InvalidParameterSpecException {
	if (!(params instanceof IQDSAParameterSpec)) {
	    throw new InvalidParameterSpecException("unsupported type");
	}
	IQDSAParameterSpec iqdsaParams = (IQDSAParameterSpec) params;

	discriminant = iqdsaParams.getDiscriminant();
	gamma = iqdsaParams.getGamma();
    }

    /**
     * Import the specified parameters and decode them according to the primary
     * decoding format for parameters. The primary decoding format for
     * parameters is ASN.1
     * 
     * @param encParams
     *                the encoded parameters
     * @throws IOException
     *                 on decoding errors or if the encoded parameters are
     *                 <tt>null</tt>.
     */
    public void init(byte[] encParams) throws IOException {
	if (encParams == null) {
	    throw new IOException("parameters are null");
	}

	IQDSAASN1Parameters asn1params = new IQDSAASN1Parameters();
	try {
	    ASN1Tools.derDecode(encParams, asn1params);
	    gamma = asn1params.getGamma();
	} catch (ASN1Exception asn1e) {
	    throw new IOException("ASN1Exception: " + asn1e.getMessage());
	} catch (IQEncodingException iqee) {
	    throw new IOException("IQEncodingException: " + iqee.getMessage());
	}
	discriminant = asn1params.getDiscriminant();
    }

    /**
     * Imports the parameters from <tt>params</tt> and decodes them according
     * to the specified decoding scheme. If <tt>format</tt> is null, the
     * primary decoding format for parameters is used. The primary decoding
     * format is ASN.1
     * 
     * @param params
     *                the encoded parameters.
     * 
     * @param format
     *                the name of the decoding scheme.
     * 
     * @throws IOException
     *                 on decoding errors, or if this parameter object has
     *                 already been initialized.
     */
    public void init(byte[] params, String format) throws IOException {
	if (format == null || format.equals("ASN.1")) {
	    init(params);
	} else {
	    throw new IOException("encoding format \"" + format
		    + "\" not supported.");
	}
    }

    /**
     * Returns the parameters in their primary encoding format. The primary
     * encoding format for parameters is ASN.1
     * 
     * @return the parameters encoded using their primary encoding format.
     * 
     * @throws IOException
     *                 on encoding errors, or if this parameter object has not
     *                 been initialized.
     */
    public byte[] getEncoded() throws IOException {
	IQDSAASN1Parameters asn1params = new IQDSAASN1Parameters(discriminant,
		gamma);
	try {
	    return ASN1Tools.derEncode(asn1params);
	} catch (RuntimeException re) {
	    throw new IOException(re.getMessage());
	}
    }

    /**
     * Returns the parameters encoded in the specified scheme. If
     * <tt>format</tt> is null, the primary encoding format for parameters is
     * used. The primary encoding format is ASN.1
     * 
     * @param format
     *                the name of the encoding format.
     * 
     * @return the parameters encoded using the specified encoding scheme.
     * 
     * @throws IOException
     *                 on encoding errors, or if this parameter object has not
     *                 been initialized.
     */
    public byte[] getEncoded(String format) throws IOException {
	if (format == null || format.equals("ASN.1")) {
	    return getEncoded();
	}
	throw new IOException("encoding format \"" + format
		+ "\" not supported.");
    }

    /**
     * Returns a (transparent) specification of this parameter object.
     * <tt>paramSpec</tt> identifies the specification class in which the
     * parameters should be returned.
     * 
     * @param paramSpec
     *                the specification class in which the parameters should be
     *                returned
     * @return the parameter specification
     * @throws InvalidParameterSpecException
     *                 if the requested parameter specification is inappropriate
     *                 for this parameter object, or if this parameter object
     *                 has not been initialized.
     */
    public AlgorithmParameterSpec getParameterSpec(Class paramSpec)
	    throws InvalidParameterSpecException {
	if (!paramSpec.isAssignableFrom(IQDSAParameterSpec.class)) {
	    throw new InvalidParameterSpecException("unsupported type");
	}
	return new IQDSAParameterSpec(discriminant, gamma);
    }

    /**
     * Returns a formatted string describing the parameters.
     * 
     * @return a formatted string describing the parameters, or null if this
     *         parameter object has not been initialized.
     */
    public String toString() {
	return "discriminant = " + discriminant + ", gamma = " + gamma;
    }

    /**
     * @return the ASN.1 parameters structure
     */
    protected IQDSAASN1Parameters getASN1Params() {
	return new IQDSAASN1Parameters(discriminant, gamma);
    }

}
