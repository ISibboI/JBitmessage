/*
 * Copyright (c) 1998-2003 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */

package de.flexiprovider.core.dsa;

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
 * This class represents the DSA parameters p, q, g.
 * 
 * @author Thomas Wahrenbruch
 */
public class DSAParameters extends AlgorithmParameters {

    /**
     * The OID of DSA.
     */
    public static final String OID = DSAKeyFactory.OID;

    /**
     * An alternative OID of DSA.
     */
    public static final String OID2 = DSAKeyFactory.OID2;

    // the prime p
    private FlexiBigInt p;

    // the subprime q
    private FlexiBigInt q;

    // the generator g
    private FlexiBigInt g;

    /**
     * Inner class providing the DSA ASN.1 parameters structure.
     * <p>
     * The ASN.1 parameters structure is defined as follows:
     * 
     * <pre>
     * DSAAlgorithmParameters ::= SEQUENCE {
     *   p INTEGER,   -- the prime p
     *   q INTEGER,   -- the subprime q
     *   g INTEGER,   -- the generator g
     * }
     * </pre>
     */
    private static class DSAASN1Parameters extends ASN1Sequence {

	// the prime p
	private ASN1Integer p;

	// the subprime q
	private ASN1Integer q;

	// the generator g
	private ASN1Integer g;

	/**
	 * Constructs a new ASN.1 Structure.
	 */
	public DSAASN1Parameters() {
	    super(3);
	    p = new ASN1Integer();
	    q = new ASN1Integer();
	    g = new ASN1Integer();

	    add(p);
	    add(q);
	    add(g);
	}

	/**
	 * Constructs a new ASN.1 Structure with the given p,q and g.
	 * 
	 * @param p
	 *                the prime p.
	 * @param q
	 *                the subprime q.
	 * @param g
	 *                the generator g.
	 */
	public DSAASN1Parameters(FlexiBigInt p, FlexiBigInt q, FlexiBigInt g) {
	    super(3);
	    this.p = ASN1Tools.createInteger(p);
	    this.q = ASN1Tools.createInteger(q);
	    this.g = ASN1Tools.createInteger(g);

	    add(this.p);
	    add(this.q);
	    add(this.g);
	}

	/**
	 * @return the generator g
	 */
	public FlexiBigInt getG() {
	    return ASN1Tools.getFlexiBigInt(g);
	}

	/**
	 * @return the prime p
	 */
	public FlexiBigInt getP() {
	    return ASN1Tools.getFlexiBigInt(p);
	}

	/**
	 * @return the subprime q
	 */
	public FlexiBigInt getQ() {
	    return ASN1Tools.getFlexiBigInt(q);
	}

    }

    /**
     * Initialize this parameters object using the given parameter
     * specification. The parameter specification has to be an instance of
     * {@link DSAParameterSpec}.
     * 
     * @param params
     *                the parameter specification
     * @throws InvalidParameterSpecException
     *                 if the parameter specification is <tt>null</tt> or of
     *                 an unsupported type.
     */
    public void init(AlgorithmParameterSpec params)
	    throws InvalidParameterSpecException {

	if (!(params instanceof DSAParameterSpec)) {
	    throw new InvalidParameterSpecException("unsupported type");
	}
	DSAParameterSpec dsaSpec = (DSAParameterSpec) params;

	p = dsaSpec.getPrimeP();
	q = dsaSpec.getPrimeQ();
	g = dsaSpec.getBaseG();
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

	try {
	    DSAASN1Parameters asn1dsaParams = new DSAASN1Parameters();
	    ASN1Tools.derDecode(encParams, asn1dsaParams);

	    p = asn1dsaParams.getP();
	    q = asn1dsaParams.getQ();
	    g = asn1dsaParams.getG();

	} catch (ASN1Exception ae) {
	    throw new IOException("unable to decode parameters.");
	}
    }

    /**
     * Import the specified parameters and decode them according to the
     * specified decoding format. Currently, only the primary decoding format is
     * supported.
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
     * 
     * @return the encoded parameters
     */
    public byte[] getEncoded() {
	DSAASN1Parameters asn1dsaParams = new DSAASN1Parameters(p, q, g);
	return ASN1Tools.derEncode(asn1dsaParams);
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
     * Return a (transparent) specification of this parameters object. paramSpec
     * identifies the specification class in which the parameters should be
     * returned. Currently only DSAParameterSpec is supported.
     * 
     * @param paramSpec
     *                the the specification class in which the parameters should
     *                be returned.
     * @return the parameter specification.
     * @throws InvalidParameterSpecException
     *                 if the requested parameter specification is inappropriate
     *                 for this parameter object.
     */
    public AlgorithmParameterSpec getParameterSpec(Class paramSpec)
	    throws InvalidParameterSpecException {

	if ((paramSpec == null)
		|| !paramSpec.isAssignableFrom(DSAParameterSpec.class)) {
	    throw new InvalidParameterSpecException("unsupported type");
	}

	return new DSAParameterSpec(p, q, g);
    }

    /**
     * @return a human readable form of the parameters
     */
    public String toString() {
	return "p: 0x" + p.toString(16) + "\n" + "q: 0x" + q.toString(16)
		+ "\n" + "g: 0x" + g.toString(16);

    }

    /**
     * @return the (unencoded) ASN.1 parameters structure
     */
    protected DSAASN1Parameters getASN1Parameters() {
	return new DSAASN1Parameters(p, q, g);
    }

}
