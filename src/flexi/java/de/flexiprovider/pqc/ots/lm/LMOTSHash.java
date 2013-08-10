package de.flexiprovider.pqc.ots.lm;

import java.io.IOException;
import java.util.Vector;

import codec.asn1.ASN1Exception;
import de.flexiprovider.common.math.polynomials.GFP32Polynomial;

/**
 * This class implements the hash function used for the signature. It is
 * described in the paper on page 7 (2.3 A hash function family)
 * 
 */
public class LMOTSHash {

	private int m;
	private Vector a;

	/**
	 * Constructor using an encoded byte Array to construct an LMOTS Hash. The
	 * byte array must comply to the encoding format of LMOTS Hash. Using
	 * .getEncoded() yields a suitable byte array.
	 * 
	 * @param encoded
	 *            the byte array to be decoded.
	 */
	public LMOTSHash(byte[] encoded) {
		GFPVectorSerial serial = new GFPVectorSerial(encoded);
		a = serial.getVectorRepresentation();
		m = a.size();
	}

	/**
	 * Constructor
	 * 
	 * @param a
	 *            a vector of {@link GFP32Polynomial}
	 */
	public LMOTSHash(Vector a) {
		this.a = a;
		m = a.size();
	}

	/**
	 * this method calculates the hash of a given vector of
	 * {@link GFP32Polynomial}
	 * 
	 * @param vec
	 *            a vector of {@link GFP32Polynomial}
	 * @return a {@link GFP32Polynomial}
	 */
	public GFP32Polynomial calculatHash(Vector vec) {
		Vector intermediateResult = new Vector();

		for (int i = m; i > 0; i--) {
			intermediateResult.addElement(((GFP32Polynomial) a.elementAt(i - 1)).multiply((GFP32Polynomial) vec
					.elementAt(i - 1)));
		}

		return elementSum(intermediateResult);
	}

	private GFP32Polynomial elementSum(Vector v) {
		int size = v.size();
		GFP32Polynomial result = (GFP32Polynomial) v.elementAt(size - 1);

		for (int j = size - 1; j > 0; j--) {
			result.addToThis((GFP32Polynomial) v.elementAt(j - 1));
		}

		return result;
	}

	// TODO: only for testing
	public Vector getA() {
		return a;
	}

	public byte[] getEncoded() throws ASN1Exception, IOException {
		GFPVectorSerial serial = new GFPVectorSerial(a);

		return serial.getArrayRepresentation();
	}
}
