package de.flexiprovider.nf.iq.iqgq;

import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1OctetString;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1Type;
import de.flexiprovider.api.exceptions.InvalidParameterSpecException;
import de.flexiprovider.api.keys.PrivateKey;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.math.quadraticfields.QuadraticIdeal;
import de.flexiprovider.common.util.ASN1Tools;

/**
 * Class for private keys pertaining to the IQGQ algorithm
 * 
 * @author Ralf-P. Weinmann
 * @see PrivateKey
 */
public class IQGQPrivateKey extends PrivateKey {

    private IQGQParameterSpec params;

    private QuadraticIdeal theta;

    private FlexiBigInt exponent;

    protected IQGQPrivateKey(IQGQParameterSpec params, QuadraticIdeal theta,
	    FlexiBigInt exponent) {
	this.params = params;
	this.theta = theta;
	this.exponent = exponent;
    }

    /**
     * Construct an IQGQPrivateKey from the given key specification.
     * 
     * @param keySpec
     *                the key specification
     */
    protected IQGQPrivateKey(IQGQPrivateKeySpec keySpec) {
	this(keySpec.getParams(), keySpec.getTheta(), keySpec.getExponent());
    }

    /**
     * Return the standard algorithm name for this key.
     * 
     * @return "IQGQ"
     */
    public String getAlgorithm() {
	return "IQGQ";
    }

    /**
     * @return the parameters
     */
    public IQGQParameterSpec getParams() {
	return params;
    }

    /**
     * @return theta
     */
    public QuadraticIdeal getTheta() {
	return theta;
    }

    /**
     * @return the exponent
     */
    public FlexiBigInt getExponent() {
	return exponent;
    }

    /**
     * @return a human-readable form of the key
     */
    public String toString() {
	return "parameters = " + params + ", theta = " + theta
		+ ", exponent = " + exponent;

    }

    public boolean equals(Object obj) {
	if (!(obj instanceof IQGQPrivateKey)) {
	    return false;
	}
	IQGQPrivateKey oKey = (IQGQPrivateKey) obj;

	return exponent.equals(oKey.exponent) && theta.equals(oKey.theta)
		&& params.equals(oKey.params);
    }

    public int hashCode() {
	return theta.hashCode() + exponent.hashCode() + params.hashCode();
    }

    protected ASN1Type getAlgParams() {
	IQGQParameters iqdsaParams = new IQGQParameters();
	try {
	    iqdsaParams.init(params);
	} catch (InvalidParameterSpecException e) {
	    // the parameters are correct and must be accepted
	    throw new RuntimeException("internal error");
	}
	return iqdsaParams.getASN1Params();
    }

    protected byte[] getKeyData() {
	ASN1Sequence keyData = new ASN1Sequence(2);
	keyData.add(new ASN1OctetString(theta.idealToOctets(params
		.getDiscriminant(), false)));
	keyData.add(ASN1Tools.createInteger(exponent));
	return ASN1Tools.derEncode(keyData);
    }

    protected ASN1ObjectIdentifier getOID() {
	return new ASN1ObjectIdentifier(IQGQKeyFactory.OID);
    }

}
