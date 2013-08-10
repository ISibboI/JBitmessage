package de.flexiprovider.pqc.rainbow;

import codec.asn1.ASN1Integer;
import codec.asn1.ASN1Null;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1OctetString;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1SequenceOf;
import codec.asn1.ASN1Type;
import de.flexiprovider.api.keys.PublicKey;
import de.flexiprovider.common.util.ASN1Tools;
import de.flexiprovider.pqc.rainbow.util.RainbowUtil;

/**
 * This class extends PublicKey of the FlexiProvider_API and implements,
 * respectively overrides its methods for the Rainbow Signature Scheme.
 * 
 * The public key in Rainbow consists of n - v1 polynomial components of the
 * private key's F and the field structure of the finite field k.
 * 
 * The quadratic (or mixed) coefficients of the polynomials from the public key
 * are stored in the 2-dimensional array in lexicographical order, requiring n *
 * (n + 1) / 2 entries for each polynomial. The singular terms are stored in a
 * 2-dimensional array requiring n entries per polynomial, the scalar term of
 * each polynomial is stored in a 1-dimensional array.
 * 
 * More detailed information on the public key is to be found in the paper of
 * Jintai Ding, Dieter Schmidt: Rainbow, a New Multivariable Polynomial
 * Signature Scheme. ACNS 2005: 164-175 (http://dx.doi.org/10.1007/11496137_12)
 * 
 * @author Patrick Neugebauer
 * @author Marius Senftleben
 * @author Tsvetoslava Vateva
 * 
 * @see RainbowKeyPairGenerator
 */
public class RainbowPublicKey extends PublicKey {

	// the OID of the algorithm
	private String oid;

	private short[][] coeffquadratic;
	private short[][] coeffsingular;
	private short[] coeffscalar;
	private int docLength; // length of possible document to sign

	/**
	 * Constructor used by {@link RainbowKeyPairGenerator}.
	 * 
	 * @param oid
	 * @param docLength
	 * @param coeffQuadratic
	 * @param coeffSingular
	 * @param coeffScalar
	 */
	public RainbowPublicKey(String oid, int docLength,
			short[][] coeffQuadratic, short[][] coeffSingular,
			short[] coeffScalar) {
		this.oid = oid;
		this.docLength = docLength;
		this.coeffquadratic = coeffQuadratic;
		this.coeffsingular = coeffSingular;
		this.coeffscalar = coeffScalar;

	}

	/**
	 * Constructor (used by the {@link RainbowKeyFactory}).
	 * 
	 * @param keySpec
	 *            a {@link rainbowPublicKeySpec}
	 */
	protected RainbowPublicKey(RainbowPublicKeySpec keySpec) {
		this(keySpec.getOIDString(), keySpec.getDocLength(), keySpec.getCoeffquadratic(), keySpec
				.getCoeffsingular(), keySpec.getCoeffscalar());
	}

	/**
	 * @return the docLength
	 */
	public int getDocLength() {
		return this.docLength;
	}

	/**
	 * @return the coeffquadratic
	 */
	protected short[][] getCoeffquadratic() {
		return coeffquadratic;
	}

	/**
	 * @param coeffquadratic
	 *            the coeffquadratic to set
	 */
	protected void setCoeffquadratic(short[][] coeffquadratic) {
		this.coeffquadratic = coeffquadratic;
	}

	/**
	 * @return the coeffsingular
	 */
	protected short[][] getCoeffsingular() {
		return coeffsingular;
	}

	/**
	 * @param coeffsingular
	 *            the coeffsingular to set
	 */
	protected void setCoeffsingular(short[][] coeffsingular) {
		this.coeffsingular = coeffsingular;
	}

	/**
	 * @return the coeffscalar
	 */
	protected short[] getCoeffscalar() {
		return coeffscalar;
	}

	/**
	 * @param coeffscalar
	 *            the coeffscalar to set
	 */
	protected void setCoeffscalar(short[] coeffscalar) {
		this.coeffscalar = coeffscalar;
	}

	/**
	 * Compare this Rainbow public key with another object.
	 * 
	 * @param other
	 *            the other object
	 * @return the result of the comparison
	 */
	public boolean equals(Object other) {
		if (other == null || !(other instanceof RainbowPublicKey)) {
			return false;
		}
		RainbowPublicKey otherKey = (RainbowPublicKey) other;

		boolean eq;
		// compare using shortcut rule ( && instead of &)
		eq = oid.equals(otherKey.getOIDString());
		eq = docLength == otherKey.getDocLength();
		eq = eq
				&& RainbowUtil.equals(coeffquadratic, otherKey
						.getCoeffquadratic());
		eq = eq
				&& RainbowUtil.equals(coeffsingular, otherKey
						.getCoeffsingular());
		eq = eq && RainbowUtil.equals(coeffscalar, otherKey.getCoeffscalar());
		return eq;
	}

	/**
	 * @return name of the algorithm - "Rainbow"
	 */
	public final String getAlgorithm() {
		return "Rainbow";
	}

	/**
	 * @return the OID of the algorithm
	 */
	protected String getOIDString() {
		return oid;
	}

	/**
	 * @return the OID to encode in the SubjectPublicKeyInfo structure
	 */
	protected ASN1ObjectIdentifier getOID() {
		return new ASN1ObjectIdentifier(RainbowKeyFactory.OID);
	}

	/**
	 * @return the algorithm parameters to encode in the SubjectPublicKeyInfo
	 *         structure
	 */
	protected ASN1Type getAlgParams() {
		// TODO maybe we pub vi[] here call method from RainbowParameterSpec?
		return new ASN1Null();
	}

	/**
	 * Return the keyData to encode in the SubjectPublicKeyInfo structure.
	 * <p>
	 * The ASN.1 definition of the key structure is
	 * 
	 * <pre>
	 *       RainbowPublicKey ::= SEQUENCE {
	 *         oid        OBJECT IDENTIFIER         -- OID identifying the algorithm
	 *         docLength        Integer      	     -- length of the code
	 *         coeffquadratic   SEQUENCE OF OCTET STRING -- quadratic (mixed) coefficients
	 *         coeffsingular	SEQUENCE OF OCTET STRING -- singular coefficients
	 *         coeffscalar	SEQUENCE OF OCTET STRING -- scalar coefficients
	 *       }
	 * </pre>
	 * 
	 * @return the keyData to encode in the SubjectPublicKeyInfo structure
	 */
	protected byte[] getKeyData() {
		ASN1Sequence keyData = new ASN1Sequence();

		// encode <oidString>
		keyData.add(new ASN1ObjectIdentifier(oid));

		// encode <docLength>
		keyData.add(new ASN1Integer(docLength));

		// encode <coeffQuadratic>
		ASN1SequenceOf asnCoeffQuad = new ASN1SequenceOf(ASN1OctetString.class);
		for (int i = 0; i < coeffquadratic.length; i++) {
			asnCoeffQuad.add(new ASN1OctetString(RainbowUtil
					.convertArray(coeffquadratic[i])));
		}
		keyData.add(asnCoeffQuad);

		// encode <coeffSingular>
		ASN1SequenceOf asnCoeffSing = new ASN1SequenceOf(ASN1OctetString.class);
		for (int i = 0; i < coeffsingular.length; i++) {
			asnCoeffSing.add(new ASN1OctetString(RainbowUtil
					.convertArray(coeffsingular[i])));
		}
		keyData.add(asnCoeffSing);

		// encode <coeffScalar>
		keyData.add(new ASN1OctetString(RainbowUtil.convertArray(coeffscalar)));

		return ASN1Tools.derEncode(keyData);
	}

}
