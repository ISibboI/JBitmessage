package de.flexiprovider.nf.iq.iqrdsa;

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
 * Class for public keys pertaining to the IQRDSA algorithm
 * 
 * @author Ralf-P. Weinmann
 * @see PublicKey
 */
public class IQRDSAPublicKey extends PublicKey {

    private QuadraticIdeal gamma;

    private QuadraticIdeal alpha;

    private IQRDSAParameterSpec params;

    /**
     * Construct an IQRDSA public key from the given parameters, public key
     * value and base element of the NFDL-problem.
     * 
     * @param params
     *                parameters consisting of gamma and prime modulus
     * @param alpha
     *                the public key value
     * @param gamma
     *                the base element of the NFDL-problem
     */
    protected IQRDSAPublicKey(IQRDSAParameterSpec params, QuadraticIdeal gamma,
	    QuadraticIdeal alpha) {
	this.params = params;
	this.gamma = gamma;
	this.alpha = alpha;
    }

    /**
     * Construct an IQRDSA public key from the given key specification.
     * 
     * @param keySpec
     *                the key specification
     */
    protected IQRDSAPublicKey(IQRDSAPublicKeySpec keySpec) {
	this(keySpec.getParams(), keySpec.getGamma(), keySpec.getAlpha());
    }

    /**
     * Returns the standard algorithm name for this key.
     * 
     * @return the name of the algorithm associated with this key.
     */
    public String getAlgorithm() {
	return "IQRDSA";
    }

    /**
     * Extract alpha parameter of key
     * 
     * @return gamma
     */
    public QuadraticIdeal getGamma() {
	return gamma;
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
     * @return object of type <tt>IQDHParameterSpec</tt> specifying the domain
     *         parameters corresponding to key
     */
    public IQRDSAParameterSpec getParams() {
	return params;
    }

    /**
     * @return a human-readable form of the key
     */
    public String toString() {
	return "parameters = " + params + ", alpha = " + alpha + ", gamma = "
		+ gamma;
    }

    public boolean equals(Object obj) {
	if (obj == null || !(obj instanceof IQRDSAPublicKey)) {
	    return false;
	}

	IQRDSAPublicKey oKey = (IQRDSAPublicKey) obj;

	return oKey.alpha.equals(alpha) && oKey.gamma.equals(gamma)
		&& oKey.params.equals(params);
    }

    public int hashCode() {
	return gamma.hashCode() + alpha.hashCode();
    }

    protected ASN1Type getAlgParams() {
	IQRDSAParameters iqdsaParams = new IQRDSAParameters();
	try {
	    iqdsaParams.init(params);
	} catch (InvalidParameterSpecException e) {
	    // the parameters are correct and must be accepted
	    throw new RuntimeException("internal error");
	}
	return iqdsaParams.getASN1Params();
    }

    protected byte[] getKeyData() {
	FlexiBigInt discriminant = params.getDiscriminant();
	ASN1Sequence keyData = new ASN1Sequence();
	keyData.add(new ASN1OctetString(gamma
		.idealToOctets(discriminant, false)));
	keyData.add(new ASN1OctetString(alpha
		.idealToOctets(discriminant, false)));
	return ASN1Tools.derEncode(keyData);
    }

    protected ASN1ObjectIdentifier getOID() {
	return new ASN1ObjectIdentifier(IQRDSAKeyFactory.OID);
    }

}
