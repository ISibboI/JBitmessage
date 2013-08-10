package de.flexiprovider.pqc.rainbow;

import codec.asn1.ASN1Null;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1OctetString;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1SequenceOf;
import codec.asn1.ASN1Type;
import de.flexiprovider.api.keys.PrivateKey;
import de.flexiprovider.common.util.ASN1Tools;
import de.flexiprovider.common.util.IntUtils;
import de.flexiprovider.pqc.rainbow.util.RainbowUtil;

/**
 * This class extends PrivateKey of the FlexiProvider_API and implements,
 * respectively overrides its methods for the Rainbow Signature Scheme
 * 
 * The Private key in Rainbow consists of the linear affine maps L1, L2 and the
 * map F, consisting of quadratic polynomials. In this implementation, we
 * denote: L1 = A1*x + b1 L2 = A2*x + b2
 * 
 * The coefficients of the polynomials in F are stored in 3-dimensional arrays
 * per layer. The indices of these arrays denote the polynomial, and the
 * variables.
 * 
 * More detailed information about the private key is to be found in the paper
 * of Jintai Ding, Dieter Schmidt: Rainbow, a New Multivariable Polynomial
 * Signature Scheme. ACNS 2005: 164-175 (http://dx.doi.org/10.1007/11496137_12)
 * 
 * @author Patrick Neugebauer
 * @author Marius Senftleben
 * @author Tsvetoslava Vateva
 * 
 * @see RainbowKeyPairGenerator
 */
public class RainbowPrivateKey extends PrivateKey {
	
	// the OID of the algorithm
	private String oid; 
	
	// the inverse of L1
	private short[][] A1inv;

	// translation vector element of L1
	private short[] b1;

	// the inverse of L2
	private short[][] A2inv;

	// translation vector of L2
	private short[] b2;

	/*
	 * components of F
	 */
	private Layer[] layers;

	// set of vinegar vars per layer.
	private int[] vi;
	
	

	/**
	 * Constructor (used by the {@link RainbowKeyPairGenerator}).
	 * 
	 * @param oid
	 * @param A1inv
	 * @param b1
	 * @param A2inv
	 * @param b2
	 * @param vi
	 * @param layers
	 */
	protected RainbowPrivateKey(String oid, short[][] A1inv, short[] b1, short[][] A2inv,
			short[] b2, int[] vi, Layer[] layers) {
		this.oid = oid;
		this.A1inv = A1inv;
		this.b1 = b1;
		this.A2inv = A2inv;
		this.b2 = b2;
		this.vi = vi;
		this.layers = layers;
	}

	/**
	 * Constructor (used by the {@link RainbowKeyFactory}).
	 * 
	 * @param keySpec
	 *            a {@link RainbowPrivateKeySpec}
	 */
	protected RainbowPrivateKey(RainbowPrivateKeySpec keySpec) {
		this(keySpec.getOIDString(), keySpec.getA1inv(), keySpec.getb1(), keySpec.getA2inv(), keySpec
				.getb2(), keySpec.getVi(), keySpec.getLayers());
	}

	/**
	 * Getter for the inverse matrix of A1.
	 * 
	 * @return the A1inv inverse
	 */
	protected short[][] getA1inv() {
		return this.A1inv;
	}

	/**
	 * Getter for the translation part of the private quadratic map L1.
	 * 
	 * @return b1 the translation part of L1
	 */
	protected short[] getb1() {
		return this.b1;
	}

	/**
	 * Getter for the translation part of the private quadratic map L2.
	 * 
	 * @return b2 the translation part of L2
	 */
	protected short[] getb2() {
		return this.b2;
	}

	/**
	 * Getter for the inverse matrix of A2
	 * 
	 * @return the A2inv
	 */
	protected short[][] getA2inv() {
		return this.A2inv;
	}

	/**
	 * Returns the layers contained in the private key
	 * 
	 * @return layers
	 */
	protected Layer[] getLayers() {
		return this.layers;
	}

	/**
	 * Returns the array of vi-s
	 * 
	 * @return the vi
	 */
	protected int[] getVi() {
		return vi;
	}

	/**
	 * Compare this Rainbow private key with another object.
	 * 
	 * @param other
	 *            the other object
	 * @return the result of the comparison
	 */
	public boolean equals(Object other) {
		if (other == null || !(other instanceof RainbowPrivateKey)) {
			return false;
		}
		RainbowPrivateKey otherKey = (RainbowPrivateKey) other;

		boolean eq = true;
		// compare using shortcut rule ( && instead of &)
		eq = oid.equals(otherKey.oid);
		eq = eq && RainbowUtil.equals(A1inv, otherKey.getA1inv());
		eq = eq && RainbowUtil.equals(A2inv, otherKey.getA2inv());
		eq = eq && RainbowUtil.equals(b1, otherKey.getb1());
		eq = eq && RainbowUtil.equals(b2, otherKey.getb2());
		eq = eq && IntUtils.equals(vi, otherKey.getVi());
		if (layers.length != otherKey.getLayers().length) {
			return false;
		}
		for (int i = layers.length - 1; i >= 0; i--) {
			eq &= layers[i].equals(otherKey.getLayers()[i]);
		}
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
	 * @return the algorithm parameters to encode in the SubjectPublicKeyInfo
	 *         structure
	 */
	protected ASN1Type getAlgParams() {
		return new ASN1Null();
	}

	/**
	 * @return the OID to encode in the SubjectPublicKeyInfo structure
	 */
	protected ASN1ObjectIdentifier getOID() {
		return new ASN1ObjectIdentifier(RainbowKeyFactory.OID);
	}

	/**
	 * Return the key data to encode in the SubjectPublicKeyInfo structure.
	 * <p>
	 * The ASN.1 definition of the key structure is
	 * 
	 * <pre>
	 *   RainbowPrivateKey ::= SEQUENCE {
	 *     oid        OBJECT IDENTIFIER         -- OID identifying the algorithm
	 *     A1inv      SEQUENCE OF OCTET STRING  -- inversed matrix of L1
	 *     b1         OCTET STRING              -- translation vector of L1
	 *     A2inv      SEQUENCE OF OCTET STRING  -- inversed matrix of L2
	 *     b2         OCTET STRING              -- translation vector of L2
	 *     vi         OCTET STRING              -- num of elmts in each Set S 
	 *     layers     SEQUENCE OF Layer         -- layers of F
	 *   }
	 *   
	 *   Layer             ::= SEQUENCE OF Poly 
	 *   
	 *   Poly              ::= SEQUENCE {
	 *     alpha      SEQUENCE OF OCTET STRING
	 *     beta       SEQUENCE OF OCTET STRING
	 *     gamma      OCTET STRING
	 *     eta        INTEGER
	 *   }
	 * </pre>
	 * 
	 * @return the key data to encode in the SubjectPublicKeyInfo structure
	 */
	protected byte[] getKeyData() {
		ASN1Sequence keyData = new ASN1Sequence();

		// encode <oidString>
		keyData.add(new ASN1ObjectIdentifier(RainbowKeyFactory.OID));

		// encode <A1inv>
		ASN1SequenceOf asnA1 = new ASN1SequenceOf(ASN1OctetString.class);
		for (int i = 0; i < A1inv.length; i++) {
			asnA1.add(new ASN1OctetString(RainbowUtil.convertArray(A1inv[i])));
		}
		keyData.add(asnA1);

		// encode <b1>
		keyData.add(new ASN1OctetString(RainbowUtil.convertArray(b1)));

		// encode <A2inv>
		ASN1SequenceOf asnA2 = new ASN1SequenceOf(ASN1OctetString.class);
		for (int i = 0; i < A2inv.length; i++) {
			asnA2.add(new ASN1OctetString(RainbowUtil.convertArray(A2inv[i])));
		}
		keyData.add(asnA2);

		// encode <b2>
		keyData.add(new ASN1OctetString(RainbowUtil.convertArray(b2)));

		// encode <vi>
		keyData.add(new ASN1OctetString(RainbowUtil.convertIntArray(vi)));

		// encode <layers>
		ASN1SequenceOf asnLayers = new ASN1SequenceOf(ASN1Sequence.class);
		// a layer:
		for (int l = 0; l < this.layers.length; l++) {
			ASN1SequenceOf aLayer = new ASN1SequenceOf(ASN1Sequence.class);

			// alphas (num of alpha-2d-array = oi)
			byte[][][] alphas = RainbowUtil.convertArray(layers[l]
					.getCoeffAlpha());
			ASN1SequenceOf alphas3d = new ASN1SequenceOf(ASN1Sequence.class);
			for (int i = 0; i < alphas.length; i++) {
				ASN1SequenceOf alphas2d = new ASN1SequenceOf(
						ASN1OctetString.class);
				for (int j = 0; j < alphas[i].length; j++) {
					alphas2d.add(new ASN1OctetString(alphas[i][j]));
				}
				alphas3d.add(alphas2d);
			}
			aLayer.add(alphas3d);

			// betas ....
			byte[][][] betas = RainbowUtil.convertArray(layers[l]
					.getCoeffBeta());
			ASN1SequenceOf betas3d = new ASN1SequenceOf(ASN1Sequence.class);
			for (int i = 0; i < betas.length; i++) {
				ASN1SequenceOf betas2d = new ASN1SequenceOf(
						ASN1OctetString.class);
				for (int j = 0; j < betas[i].length; j++) {
					betas2d.add(new ASN1OctetString(betas[i][j]));
				}
				betas3d.add(betas2d);
			}
			aLayer.add(betas3d);

			// gammas ...
			byte[][] gammas = RainbowUtil.convertArray(layers[l]
					.getCoeffGamma());
			ASN1SequenceOf asnG = new ASN1SequenceOf(ASN1OctetString.class);
			for (int i = 0; i < gammas.length; i++) {
				asnG.add(new ASN1OctetString(gammas[i]));
			}
			aLayer.add(asnG);

			// eta
			aLayer.add(new ASN1OctetString(RainbowUtil.convertArray(layers[l]
					.getCoeffEta())));

			// now, layer built up. add it!
			asnLayers.add(aLayer);
		}
		keyData.add(asnLayers);

		return ASN1Tools.derEncode(keyData);
	}
}
