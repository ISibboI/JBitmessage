package de.flexiprovider.nf.iq.iqdsa;

import codec.asn1.ASN1Integer;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1Type;
import de.flexiprovider.api.exceptions.InvalidParameterSpecException;
import de.flexiprovider.api.keys.PrivateKey;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.util.ASN1Tools;

/**
 * This class represents IQDSA private keys.
 * 
 * @author Ralf-P. Weinmann
 */
public class IQDSAPrivateKey extends PrivateKey {

    private IQDSAParameterSpec params;

    private FlexiBigInt a;

    /**
     * Construct an IQDSA private key from the given parameters and integer.
     * 
     * @param params
     *                the parameters
     * @param a
     *                the integer
     */
    protected IQDSAPrivateKey(IQDSAParameterSpec params, FlexiBigInt a) {
	this.params = params;
	this.a = a;
    }

    /**
     * Construct an IQDSA private key from the given key specification.
     * 
     * @param keySpec
     *                the key specification
     */
    protected IQDSAPrivateKey(IQDSAPrivateKeySpec keySpec) {
	this(keySpec.getParams(), keySpec.getA());
    }

    /**
     * Returns the standard algorithm name for this key.
     * 
     * @return the name of the algorithm associated with this key.
     */
    public String getAlgorithm() {
	return "IQDSA";
    }

    /**
     * @return the parameters
     */
    protected IQDSAParameterSpec getParams() {
	return params;
    }

    /**
     * @return the integer <tt>a</tt>
     */
    protected FlexiBigInt getA() {
	return a;
    }

    /**
     * @return a human-readable form of the key
     */
    public String toString() {
	return "parameters = " + params + ", a = " + a;
    }

    public boolean equals(Object other) {
	if (!(other instanceof IQDSAPrivateKey)) {
	    return false;
	}
	IQDSAPrivateKey oKey = (IQDSAPrivateKey) other;

	return params.equals(oKey.params) && a.equals(oKey.a);
    }

    public int hashCode() {
	return a.hashCode();
    }

    protected ASN1Type getAlgParams() {
	IQDSAParameters iqdsaParams = new IQDSAParameters();
	try {
	    iqdsaParams.init(params);
	} catch (InvalidParameterSpecException e) {
	    // the parameters are correct and must be accepted
	    throw new RuntimeException("internal error");
	}
	return iqdsaParams.getASN1Params();
    }

    protected byte[] getKeyData() {
	ASN1Integer asna = new ASN1Integer(a.toByteArray());
	return ASN1Tools.derEncode(asna);
    }

    protected ASN1ObjectIdentifier getOID() {
	return new ASN1ObjectIdentifier(IQDSAKeyFactory.OID);
    }

}
