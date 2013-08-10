package de.flexiprovider.pqc.tss;

import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1Type;
import de.flexiprovider.api.keys.PublicKey;

public class TSSPublicKey extends PublicKey {

	private TSSPolynomial s;

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public TSSPublicKey(TSSPolynomial s) {
		this.s = s;
	}

	public String getAlgorithm() {
		// TODO Auto-generated method stub
		return null;
	}

	protected ASN1Type getAlgParams() {
		// TODO Auto-generated method stub
		return null;
	}

	protected byte[] getKeyData() {
		byte[] pData = new byte[] {};
		try {
			pData = s.getEncoded();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return pData;
	}

	protected ASN1ObjectIdentifier getOID() {
		// TODO Auto-generated method stub
		return null;
	}

	public TSSPolynomial getS() {
		return s;
	}

}
