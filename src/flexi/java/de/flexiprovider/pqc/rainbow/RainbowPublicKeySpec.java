package de.flexiprovider.pqc.rainbow;

import codec.asn1.ASN1Integer;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1OctetString;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1SequenceOf;
import de.flexiprovider.api.keys.KeySpec;
import de.flexiprovider.common.util.ASN1Tools;
import de.flexiprovider.pqc.rainbow.util.RainbowUtil;

/**
 * This class provides a specification for a RainbowSignature public key.
 * 
 * @author Patrick Neugebauer
 * @author Marius Senftleben
 * @author Tsvetoslava Vateva
 * 
 * @see de.flexiprovider.pqc.rainbow.RainbowPublicKey
 * @see KeySpec
 */
public class RainbowPublicKeySpec implements KeySpec {

	// the OID of the algorithm
	private String oid;

	private short[][] coeffquadratic;
	private short[][] coeffsingular;
	private short[] coeffscalar;
	private int docLength; // length of possible document to sign

	/**
	 * Constructor
	 * 
	 * @param docLength
	 * @param coeffquadratic
	 * @param coeffSingular
	 * @param coeffScalar
	 */
	protected RainbowPublicKeySpec(String oid, int docLength,
			short[][] coeffquadratic, short[][] coeffSingular,
			short[] coeffScalar) {
		this.docLength = docLength;
		this.coeffquadratic = coeffquadratic;
		this.coeffsingular = coeffSingular;
		this.coeffscalar = coeffScalar;
	}

	/**
	 * Constructor used by the {@link RainbowKeyFactory}. It constructs internal
	 * data types out of these bytes got from ASN.1 decoding.
	 * 
	 * @param docLength
	 * @param coeffQuadratic
	 * @param coeffSingular
	 * @param coeffScalar
	 */
	protected RainbowPublicKeySpec(String oid, int docLength,
			byte[][] coeffQuadratic, byte[][] coeffSingular, byte[] coeffScalar) {
		this.oid = oid;
		this.docLength = docLength;
		this.coeffquadratic = RainbowUtil.convertArray(coeffQuadratic);
		this.coeffsingular = RainbowUtil.convertArray(coeffSingular);
		this.coeffscalar = RainbowUtil.convertArray(coeffScalar);
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
	public String getOIDString() {
		return oid;
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
	 * 
	 * @return the coeffsingular
	 */
	protected short[][] getCoeffsingular() {
		return coeffsingular;
	}

	/**
	 * @return the coeffscalar
	 */
	protected short[] getCoeffscalar() {
		return coeffscalar;
	}

	/**
	 * @return the OID to encode in the SubjectPublicKeyInfo structure
	 */
	protected ASN1ObjectIdentifier getOID() {
		return new ASN1ObjectIdentifier(RainbowKeyFactory.OID);
	}

	/**
	 * Return the keyData to encode in the SubjectPublicKeyInfo structure.
	 * <p>
	 * The ASN.1 definition of the key structure is
	 * 
	 * <pre>
	 *    RainbowPublicKey ::= SEQUENCE {
	 *      oid            OBJECT IDENTIFIER        -- OID identifying the algorithm
	 *      docLength      Integer      	        -- length of signable msg
	 *      coeffquadratic SEQUENCE OF OCTET STRING -- quadratic (mixed) coefficients
	 *      coeffsingular  SEQUENCE OF OCTET STRING -- singular coefficients
	 *      coeffscalar	   OCTET STRING             -- scalar coefficients
	 *       }
	 * </pre>
	 * 
	 * @return the keyData to encode in the SubjectPublicKeyInfo structure
	 */
	protected byte[] getKeyData() {
		ASN1Sequence keyData = new ASN1Sequence();
		keyData.add(new ASN1Integer(docLength));

		// encode <oidString>
		keyData.add(new ASN1ObjectIdentifier(RainbowKeyFactory.OID));

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
