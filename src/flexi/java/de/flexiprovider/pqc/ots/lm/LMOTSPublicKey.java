package de.flexiprovider.pqc.ots.lm;

import java.io.ByteArrayInputStream;

import codec.asn1.ASN1Null;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1OctetString;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1Type;
import codec.asn1.DERDecoder;
import codec.x509.SubjectPublicKeyInfo;
import de.flexiprovider.api.keys.PublicKey;
import de.flexiprovider.common.math.polynomials.GFP32Polynomial;
import de.flexiprovider.common.util.ASN1Tools;

/**
 * This class implements a LMOTS public key.
 * 
 * @see LMOTSKeyPairGenerator
 */
public class LMOTSPublicKey extends PublicKey {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private GFP32Polynomial hashedK;
	private GFP32Polynomial hashedL;

	private static final String OID = "1.3.6.1.4.1.8301.3.1.3.1.4";

	private LMOTSHash hFunction;

	public LMOTSPublicKey(byte[] encoded) throws Exception {

		ByteArrayInputStream in = new ByteArrayInputStream(encoded);
		DERDecoder decoder = new DERDecoder(in);

		SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo();
		spki.decode(decoder);
		in.close();

		byte[] encodedKey = spki.getRawKey();
		in = new ByteArrayInputStream(encodedKey);

		decoder = new DERDecoder(in);

		ASN1Sequence seq = new ASN1Sequence();

		ASN1OctetString hk = new ASN1OctetString();
		ASN1OctetString hl = new ASN1OctetString();
		ASN1OctetString hf = new ASN1OctetString();
		seq.add(hk);
		seq.add(hl);
		seq.add(hf);

		seq.decode(decoder);
		in.close();

		GFP32Polynomial hashedK = new GFP32Polynomial(hk.getByteArray());
		GFP32Polynomial hashedL = new GFP32Polynomial(hl.getByteArray());
		LMOTSHash hFunction = new LMOTSHash(hf.getByteArray());

		this.hashedK = hashedK;
		this.hashedL = hashedL;
		this.hFunction = hFunction;
	}

	/**
	 * Construct a new public LMOTS key.
	 * 
	 * @param hFunction
	 *            the Hash function for further use
	 * @param hk
	 *            the hash value of the Vector K of the private Key
	 * @param hl
	 *            the hash value of the Vector L of the private Key
	 */
	public LMOTSPublicKey(LMOTSHash hFunction, GFP32Polynomial hk,
			GFP32Polynomial hl) {
		hashedK = hk;
		hashedL = hl;

		this.hFunction = hFunction;
	}

	/**
	 * @return the OID of the used Algorithm (NOT USED)
	 */
	public String getAlgorithm() {
		return null;
	}

	/**
	 * this method is not used in this implementation
	 * 
	 * @return null
	 */
	protected ASN1Type getAlgParams() {
		return new ASN1Null();
	}

	/**
	 * @return the hashed value of K
	 */
	public GFP32Polynomial getHashedK() {
		return hashedK;
	}

	/**
	 * @return the hashed value of L
	 */
	public GFP32Polynomial getHashedL() {
		return hashedL;
	}

	/**
	 * @return the currently used Hash Function
	 */
	public LMOTSHash getHashFunction() {
		return hFunction;
	}

	/**
	 * this method is not used in this implementation
	 * 
	 * @return null
	 */
	protected byte[] getKeyData() {
		ASN1Sequence keyData = new ASN1Sequence();

		// encode public key bytes
		byte[] hk = null;
		byte[] hl = null;
		byte[] hf = null;
		try {
			hk = hashedK.getEncoded();
			hl = hashedL.getEncoded();
			hf = hFunction.getEncoded();
		} catch (Exception e) {
			e.printStackTrace();
		}
		keyData.add(new ASN1OctetString(hk));
		keyData.add(new ASN1OctetString(hl));
		keyData.add(new ASN1OctetString(hf));

		return ASN1Tools.derEncode(keyData);
	}

	/**
	 * this method is not used in this implementation
	 * 
	 * @return null
	 */
	protected ASN1ObjectIdentifier getOID() {
		return new ASN1ObjectIdentifier(OID);
	}

}
