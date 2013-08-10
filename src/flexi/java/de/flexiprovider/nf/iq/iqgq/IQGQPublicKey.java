package de.flexiprovider.nf.iq.iqgq;

import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1OctetString;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1Type;
import de.flexiprovider.api.exceptions.InvalidParameterSpecException;
import de.flexiprovider.api.keys.PublicKey;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.math.quadraticfields.QuadraticIdeal;
import de.flexiprovider.common.util.ASN1Tools;

/**
 * Class for public keys pertaining to the IQGQ algorithm
 * 
 * @author Ralf-P. Weinmann
 * @see PublicKey
 */
public class IQGQPublicKey extends PublicKey {

    private IQGQParameterSpec params;

    private QuadraticIdeal alpha;

    private FlexiBigInt exponent;

    protected IQGQPublicKey(IQGQParameterSpec params, QuadraticIdeal alpha,
	    FlexiBigInt exponent) {
	this.params = params;
	this.exponent = exponent;
	this.alpha = alpha;
    }

    /**
     * Construct an IQGQPubKey from the given key specification.
     * 
     * @param keySpec
     *                the key specification
     */
    protected IQGQPublicKey(IQGQPublicKeySpec keySpec) {
	this(keySpec.getParams(), keySpec.getAlpha(), keySpec.getExponent());
    }

    /**
     * Returns the standard algorithm name for this key.
     * 
     * @return the name of the algorithm associated with this key.
     */
    public String getAlgorithm() {
	return "IQGQ";
    }

    /**
     * Extract exponent of key
     * 
     * @return exponent
     */
    public FlexiBigInt getExponent() {
	return exponent;
    }

    /**
     * Extract alpha parameter of key
     * 
     * @return alpha
     */
    public QuadraticIdeal getAlpha() {
	return alpha;
    }

    /**
     * Extract parameter set from key.
     * 
     * @return object of type <tt>IQGQParameterSpec</tt> specifying the domain
     *         parameters corresponding to key
     */
    public IQGQParameterSpec getParams() {
	return params;
    }

    /**
     * @return a human-readable form of the key
     */
    public String toString() {
	return "parameters = " + params + ", exponent = " + exponent
		+ ", alpha = " + alpha;
    }

    public boolean equals(Object obj) {
	if (!(obj instanceof IQGQPublicKey)) {
	    return false;
	}
	IQGQPublicKey oKey = (IQGQPublicKey) obj;

	return exponent.equals(oKey.exponent) && alpha.equals(oKey.alpha)
		&& params.equals(oKey.params);
    }

    public int hashCode() {
	return alpha.hashCode() + exponent.hashCode() + params.hashCode();
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
	keyData.add(new ASN1OctetString(alpha.idealToOctets(params
		.getDiscriminant(), false)));
	keyData.add(ASN1Tools.createInteger(exponent));
	return ASN1Tools.derEncode(keyData);
    }

    protected ASN1ObjectIdentifier getOID() {
	return new ASN1ObjectIdentifier(IQGQKeyFactory.OID);
    }

}
