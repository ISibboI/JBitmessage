package de.flexiprovider.nf.iq.iqdsa;

import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1OctetString;
import codec.asn1.ASN1Type;
import de.flexiprovider.api.exceptions.InvalidParameterSpecException;
import de.flexiprovider.api.keys.PublicKey;
import de.flexiprovider.common.math.quadraticfields.QuadraticIdeal;
import de.flexiprovider.common.util.ASN1Tools;

/**
 * This class represents IQDSA public keys.
 * 
 * @author Ralf-P. Weinmann
 */
public class IQDSAPublicKey extends PublicKey {

    private IQDSAParameterSpec params;

    private QuadraticIdeal alpha;

    /**
     * Construct an IQDSA public key from the given parameters and the base
     * element of the NFDL-problem.
     * 
     * @param params
     *                the parameters
     * @param alpha
     *                the base element of the NFDL-problem
     */
    protected IQDSAPublicKey(IQDSAParameterSpec params, QuadraticIdeal alpha) {
	this.params = params;
	this.alpha = alpha;
    }

    /**
     * Construct an IQDSAPubKey from the given key specification.
     * 
     * @param keySpec
     *                the key specification
     */
    protected IQDSAPublicKey(IQDSAPublicKeySpec keySpec) {
	this(keySpec.getParams(), keySpec.getAlpha());
    }

    /**
     * Return the standard algorithm name for this key.
     * 
     * @return "IQDSA"
     */
    public String getAlgorithm() {
	return "IQDSA";
    }

    /**
     * @return the parameters
     */
    public IQDSAParameterSpec getParams() {
	return params;
    }

    /**
     * @return the base element of the NFDL-problem
     */
    public QuadraticIdeal getAlpha() {
	return alpha;
    }

    /**
     * @return a human-readable form of the key
     */
    public String toString() {
	return "parameters = " + params + ", alpha = " + alpha;
    }

    public boolean equals(Object other) {
	if (!(other instanceof IQDSAPublicKey)) {
	    return false;
	}
	IQDSAPublicKey oKey = (IQDSAPublicKey) other;

	return params.equals(oKey.params) && alpha.equals(oKey.alpha);
    }

    public int hashCode() {
	return params.hashCode() + alpha.hashCode();
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
	ASN1OctetString keyData = new ASN1OctetString(alpha.idealToOctets(
		params.getDiscriminant(), false));
	return ASN1Tools.derEncode(keyData);
    }

    protected ASN1ObjectIdentifier getOID() {
	return new ASN1ObjectIdentifier(IQDSAKeyFactory.OID);
    }

}
