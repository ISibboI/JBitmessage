package de.flexiprovider.pqc.ots.lm;

import java.util.Vector;

import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1Type;
import de.flexiprovider.api.keys.PrivateKey;

/**
 * This class implements a LMOTS private key.
 * 
 * @see LMOTSKeyPairGenerator
 */
public class LMOTSPrivateKey extends PrivateKey {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private Vector k;
	private Vector l;
	
	/**
     * Construct a new LMOTS private key.
     * 
     * @param k
     *                the randomly picked Vector of Polynomials
     *                as an element of DKi specified in the Paper
     *                on page 10
     * @param l
     *                the randomly picked Vector of Polynomials
     *                as an element of DLi specified in the Paper
     *                on page 10
     */
	public LMOTSPrivateKey(Vector k, Vector l) {
		this.k = k;
		this.l = l;
	}
	
	/**
	 * 
	 * @return returns the K parameter of this private Key
	 */
	public Vector getK() {
		return k;
	}
	
	/**
	 * 
	 * @return returns the L parameter of this private Key
	 */
	public Vector getL() {
		return l;
	}

	/**
	* this method is not used in this implementation
	* 
	* @return null
	*/
	protected ASN1Type getAlgParams() {
		//not used in this Signature spec
		return null;
	}

	/**
	* this method is not used in this implementation
	* 
	* @return null
	*/
	protected byte[] getKeyData() {
		//not used in this Signature spec
		return null;
	}

	/**
	* this method is not used in this implementation
	* 
	* @return null
	*/
	protected ASN1ObjectIdentifier getOID() {
		//not used in this Signature spec
		return null;
	}

	/**
	 * @return the OID of this Algorithm (NOT USED)
	 */
	public String getAlgorithm() {
		//not used in this Signature spec
		return null;
	}

}
