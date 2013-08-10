package de.flexiprovider.pqc.tss;

import java.util.Vector;

import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1Type;
import de.flexiprovider.api.keys.PrivateKey;

public class TSSPrivateKey extends PrivateKey {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	private Vector hashedS;

	public TSSPrivateKey(Vector privKey) {
		hashedS = privKey;
	}

	public String getAlgorithm() {
		// TODO Auto-generated method stub
		return null;
	}

	protected ASN1Type getAlgParams() {
		// TODO Auto-generated method stub
		return null;
	}

	public Vector getKey() {
		return hashedS;
	}

	protected byte[] getKeyData() {
		return (new TSSVectorSerial(hashedS)).getArrayRepresentation();
	}

	protected ASN1ObjectIdentifier getOID() {
		// TODO Auto-generated method stub
		return null;
	}

}
