package de.flexiprovider.nf.iq.iqgq;

import java.io.IOException;

import codec.asn1.ASN1Exception;
import codec.asn1.ASN1Integer;
import codec.asn1.ASN1Sequence;
import de.flexiprovider.api.exceptions.InvalidParameterSpecException;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.api.parameters.AlgorithmParameters;
import de.flexiprovider.common.math.FlexiBigInt;
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
public class IQGQParameters extends AlgorithmParameters {

    // the discriminant of the class group
    private FlexiBigInt discriminant;

    /**
     * Inner class specifying the IQGQ ASN.1 parameters structure.
     */
    private static class IQGQASN1Parameters extends ASN1Sequence {

	/**
	 * Version always is 1.
	 */
	private static final ASN1Integer version = new ASN1Integer(1);

	private ASN1Integer discriminant;

	/**
	 * Constructor.
	 */
	public IQGQASN1Parameters() {
	    super(2);
	    discriminant = new ASN1Integer();
	    add(version);
	    add(discriminant);
	}

	/**
	 * Constructor.
	 */
	public IQGQASN1Parameters(FlexiBigInt discriminant) {
	    super(2);
	    this.discriminant = ASN1Tools.createInteger(discriminant);
	    add(version);
	    add(this.discriminant);
	}

	/**
	 * @return the discriminant of the class group
	 */
	public FlexiBigInt getDiscriminant() {
	    return ASN1Tools.getFlexiBigInt(discriminant);
	}

    }

    /**
     * Initialize this parameter object using the given parameter specification.
     * 
     * @param paramSpec
     *                the parameter specification
     * @throws InvalidParameterSpecException
     *                 if the given parameter specification is inappropriate for
     *                 the initialization of this parameter object, or if this
     *                 parameter object has already been initialized.
     */
    public void init(AlgorithmParameterSpec paramSpec)
	    throws InvalidParameterSpecException {
	if (!(paramSpec instanceof IQGQParameterSpec)) {
	    throw new InvalidParameterSpecException("unsupported type");
	}
	discriminant = ((IQGQParameterSpec) paramSpec).getDiscriminant();
    }

    /**
     * Imports the specified parameters and decodes them according to the
     * primary decoding format for parameters. The primary decoding format for
     * parameters is ASN.1
     * 
     * @param params
     *                the encoded parameters.
     * @throws IOException
     *                 on decoding errors, or if this parameter object has
     *                 already been initialized. +
     */
    public void init(byte[] params) throws IOException {
	IQGQASN1Parameters asn1params = new IQGQASN1Parameters();
	try {
	    ASN1Tools.derDecode(params, asn1params);
	    discriminant = asn1params.getDiscriminant();
	} catch (ASN1Exception asn1e) {
	    throw new IOException("ASN1Exception: " + asn1e.getMessage());
	}
    }

    /**
     * Imports the parameters from <tt>params</tt> and decodes them according
     * to the specified decoding scheme. If <tt>format</tt> is null, the
     * primary decoding format for parameters is used. The primary decoding
     * format is ASN.1
     * 
     * @param params
     *                the encoded parameters.
     * @param format
     *                the name of the decoding scheme.
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
     * @throws IOException
     *                 on encoding errors, or if this parameter object has not
     *                 been initialized.
     */
    public byte[] getEncoded() throws IOException {
	IQGQASN1Parameters asn1params = new IQGQASN1Parameters(discriminant);
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
     * @return the parameters encoded using the specified encoding scheme.
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
	if (!paramSpec.isAssignableFrom(IQGQParameterSpec.class)) {
	    throw new InvalidParameterSpecException("unsupported type");
	}
	return new IQGQParameterSpec(discriminant);
    }

    /**
     * Returns a formatted string describing the parameters.
     * 
     * @return a formatted string describing the parameters, or null if this
     *         parameter object has not been initialized.
     */
    public String toString() {
	return "discriminant = " + discriminant;
    }

    /**
     * @return the ASN.1 parameters structure
     */
    protected IQGQASN1Parameters getASN1Params() {
	return new IQGQASN1Parameters(discriminant);
    }

}
