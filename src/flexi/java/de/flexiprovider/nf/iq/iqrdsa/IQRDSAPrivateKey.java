package de.flexiprovider.nf.iq.iqrdsa;

import codec.asn1.ASN1Integer;
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
 * Class for private keys pertaining to the IQRDSA algorithm
 * 
 * @author Ralf-P. Weinmann
 * @see PrivateKey
 */
public class IQRDSAPrivateKey extends PrivateKey {

    private IQRDSAParameterSpec params;

    private QuadraticIdeal gamma;

    private QuadraticIdeal alpha;

    private FlexiBigInt a;

    /**
     * Construct an IQRDSA private key from the given parameters, public key
     * value and base element of the NFDL-problem.
     * 
     * @param params
     *                parameters consisting of gamma and prime modulus
     * @param gamma
     *                the base element of the NFDL-problem
     * @param alpha
     *                the public key value
     * @param a
     *                the private key value
     */
    protected IQRDSAPrivateKey(IQRDSAParameterSpec params,
	    QuadraticIdeal gamma, QuadraticIdeal alpha, FlexiBigInt a) {
	this.params = params;
	this.gamma = gamma;
	this.alpha = alpha;
	this.a = a;
    }

    /**
     * Construct an IQRDSA private key from the given key specification.
     * 
     * @param keySpec
     *                the key specification
     */
    protected IQRDSAPrivateKey(IQRDSAPrivateKeySpec keySpec) {
	this(keySpec.getParams(), keySpec.getGamma(), keySpec.getAlpha(),
		keySpec.getA());
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
     * @return the parameters
     */
    public IQRDSAParameterSpec getParams() {
	return params;
    }

    /**
     * @return gamma
     */
    public QuadraticIdeal getGamma() {
	return gamma;
    }

    /**
     * @return alpha
     */
    public QuadraticIdeal getAlpha() {
	return alpha;
    }

    /**
     * @return a
     */
    public FlexiBigInt getA() {
	return a;
    }

    /**
     * @return a human-readable form of the key
     */
    public String toString() {
	return "parameters = " + params + ", alpha = " + alpha + ", gamma = "
		+ gamma + "a = " + a;

    }

    public boolean equals(Object obj) {
	if (obj == null || !(obj instanceof IQRDSAPrivateKey)) {
	    return false;
	}

	IQRDSAPrivateKey oKey = (IQRDSAPrivateKey) obj;

	return oKey.alpha.equals(alpha) && oKey.gamma.equals(gamma)
		&& oKey.params.equals(params) && oKey.a.equals(a);
    }

    public int hashCode() {
	return gamma.hashCode() + alpha.hashCode() + a.hashCode();
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
	keyData.add(new ASN1Integer(a.toByteArray()));
	return ASN1Tools.derEncode(keyData);
    }

    protected ASN1ObjectIdentifier getOID() {
	return new ASN1ObjectIdentifier(IQRDSAKeyFactory.OID);
    }

}
