package de.flexiprovider.pqc.tss;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Vector;

/**
 * Parses a Vector of {@link GFPPolynomial} to a byte Array and vice versa
 * 
 * This Class is primarily used for LMOTS and TSS, an equivalent functionality
 * can be accomplished with use of ASN.1, but usage of this class should be
 * slightly more efficient for this specific purpose.
 * 
 * format is as follows: For Reference, the f polynomial, the p parameter and
 * the actual polynomial of the first {@link GFPPolynomial} are always inserted
 * first, those parameters are only included afterwards individually if they
 * differ from the first. Each {@link GFPPolynomial} is prefixed by an
 * identifier to note the information included. Only the last 3 bits of the
 * identifier are used, the least significant bit denotes usage of the
 * Polynomial itself, this bit is not set only if the Polynomial is identical to
 * the first Polynomial, which should rarely happen. the second least
 * significant bit denotes the usage of the f polynomial and the third bit
 * denotes usage for the parameter p. Both of these parameters are usually the
 * same for all {@link GFPPolynomial}, so these bits are usually not set. The
 * actual Polynomials are transformed by prefixing the length of the polynomial
 * in 2 bytes and then all values of the polynomial with a static length
 * intdimension, set in this class (default value 8) for each value. The
 * Parameter p is transformed to a single value with the default length of
 * bytes, without any prefix.
 */
public class TSSVectorSerial {

	// byte size indicators, these may not be variable depending on format, DO
	// NOT TOUCH!
	private static final int intDimension = 8;
	private static final int rankDimension = 2;

	private Vector gfpVector;

	private byte[] byteArray;

	/**
	 * Constructor for a byte Array (probably useless)
	 * 
	 * @param b
	 *            a byte Array containing Vector information corresponding to
	 *            format in class description
	 * @throws Exception
	 */
	public TSSVectorSerial(byte[] b) {
		byteArray = b;

		gfpVector = parseToVector(b);
	}

	/**
	 * Constructor for a Vector
	 * 
	 * @param v
	 *            a Vector containing {@link GFPPolynomial}
	 */
	public TSSVectorSerial(Vector v) {
		gfpVector = v;
		byteArray = parseToByteArray(v);
	}

	private byte[] append(byte[] b1, byte[] b2) {
		byte[] b = new byte[b1.length + b2.length];
		System.arraycopy(b1, 0, b, 0, b1.length);
		System.arraycopy(b2, 0, b, b1.length, b2.length);
		return b;
	}

	private byte[] arrayToByte(long[] arr) {
		byte[] b = intToByte(arr.length, rankDimension);
		for (int i = 0; i < arr.length; i++) {
			b = append(b, longToByte(arr[i]));
		}
		return b;
	}

	private long[] byteToArray(byte[] b, int size) {
		long[] arr = new long[size];
		byte[] temp = new byte[intDimension];

		for (int i = size - 1; i >= 0; i--) {
			System.arraycopy(b, i * intDimension, temp, 0, intDimension);
			arr[i] = byteToLong(temp);
		}

		return arr;
	}

	public byte[] getArrayRepresentation() {
		return byteArray;
	}

	public Vector getVectorRepresentation() {
		return gfpVector;
	}

	private byte[] gfpToByte(TSSPolynomial gfp, TSSPolynomial compare) {
		byte[] b = new byte[1];
		if (gfp.equals(compare)) {
			return b;
		} else {
			if (gfp.paramEqual(compare)) {
				// standard procedure
				b[0] = 0x01;
				return append(b, arrayToByte(gfp.getPoly()));
			} else {
				if (!gfp.arrEqual(gfp.getF(), compare.getF())) {
					b[0] += 0x02;
					b = append(b, arrayToByte(gfp.getF()));
				}
				if (gfp.getP() != compare.getP()) {
					b[0] += 0x04;
					b = append(b, longToByte(gfp.getP()));
				}
				if (!gfp.arrEqual(gfp.getPoly(), compare.getPoly())) {
					b[0] += 0x01;
					b = append(b, arrayToByte(gfp.getPoly()));
				}
				return b;
			}
		}
	}

	private byte[] longToByte(long l) {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(bos);
		try {
			dos.writeLong(l);
			dos.flush();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		byte[] data = bos.toByteArray();
		if (data.length != 8) {
			System.err.println("Corrupted byte Array length");
		}
		return data;
	}

	private int byteToInt(byte[] b) {
		int k = 0;
		for (int i = 0; i < b.length; i++) {
			k |= (b[b.length - 1 - i] & 0xff) << (i << 3);
		}
		return k;
	}

	private byte[] intToByte(int i, int size) {
		byte[] data = new byte[size];
		for (int j = 0; j < size; j++) {
			int shift = j << 3;
			data[size - 1 - j] = (byte) ((i & 0xff << shift) >>> shift);
		}
		return data;
	}

	private long byteToLong(byte[] b) {
		ByteArrayInputStream bis = new ByteArrayInputStream(b);
		DataInputStream dis = new DataInputStream(bis);
		long result = 0;
		try {
			result = dis.readLong();
			dis.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return result;
	}

	private byte[] parseToByteArray(Vector v) {
		int size = v.size();
		byte[] b = new byte[] { (byte) size };
		if (size == 0) {
			return b;
		}

		// first element gets special treatment
		TSSPolynomial gfp = (TSSPolynomial) v.elementAt(0);
		b = append(b, arrayToByte(gfp.getF()));
		b = append(b, longToByte(gfp.getP()));
		b = append(b, arrayToByte(gfp.getPoly()));

		for (int i = 1; i < size; i++) {
			b = append(b, gfpToByte((TSSPolynomial) v.elementAt(i), gfp));
		}

		return b;
	}

	/**
	 * Parses a byte array to a Vector of {@link GFPPolynomial}, the byte array
	 * must have been created by the corresponding method "parseToByteArray" or
	 * use the same format.
	 * 
	 * The format is as follows:
	 * 
	 * @param b
	 *            the byte array containing the Information for the Vector
	 * @return
	 */
	private Vector parseToVector(byte[] b)
			throws ArrayIndexOutOfBoundsException {
		Vector v = new Vector();
		int size = b[0];
		if (size == 0) {
			return v;
		}
		v.setSize(size);
		int counter;

		byte[] temp = new byte[rankDimension];
		System.arraycopy(b, 1, temp, 0, rankDimension);
		long fLength = byteToInt(temp) * intDimension;
		temp = new byte[(int) fLength];
		// 1 for amount of gfps (number)
		counter = 1 + rankDimension;
		System.arraycopy(b, counter, temp, 0, (int) fLength);
		counter += fLength;
		long[] refF = byteToArray(temp, (int) (fLength / intDimension));

		temp = new byte[intDimension];
		System.arraycopy(b, counter, temp, 0, intDimension);
		counter += intDimension;

		long refP = byteToLong(temp);

		temp = new byte[rankDimension];
		System.arraycopy(b, counter, temp, 0, rankDimension);
		counter += rankDimension;

		long polyLength = byteToInt(temp) * intDimension;
		temp = new byte[(int) polyLength];
		System.arraycopy(b, counter, temp, 0, (int) polyLength);
		counter += polyLength;

		long[] refPoly = byteToArray(temp, (int) (polyLength / intDimension));

		v.setElementAt(new TSSPolynomial(refF, refP, refPoly), 0);

		for (int i = 1; i < size; i++) {
			byte id = b[counter];
			counter += 1;
			long[] f = refF;
			long[] poly = refPoly;
			long p = refP;

			if (id == 0x01) {
				// standard procedure
				temp = new byte[rankDimension];
				System.arraycopy(b, counter, temp, 0, rankDimension);
				counter += rankDimension;
				polyLength = byteToInt(temp) * intDimension;

				temp = new byte[(int) polyLength];

				System.arraycopy(b, counter, temp, 0, (int) polyLength);
				counter += polyLength;

				poly = byteToArray(temp, (int) (polyLength / intDimension));
			} else {
				if ((id & 0x02) != 0) {
					temp = new byte[rankDimension];
					System.arraycopy(b, counter, temp, 0, rankDimension);
					counter += rankDimension;
					fLength = byteToInt(temp) * intDimension;

					temp = new byte[(int) fLength];
					System.arraycopy(b, counter, temp, 0, (int) fLength);
					counter += fLength;

					f = byteToArray(temp, (int) (fLength / intDimension));
				}
				if ((id & 0x04) != 0) {
					temp = new byte[intDimension];
					System.arraycopy(b, counter, temp, 0, intDimension);
					counter += intDimension;

					p = byteToLong(temp);
				}
				if ((id & 0x01) != 0) {
					temp = new byte[rankDimension];
					System.arraycopy(b, counter, temp, 0, rankDimension);
					counter += rankDimension;
					polyLength = byteToInt(temp) * intDimension;

					temp = new byte[(int) polyLength];
					System.arraycopy(b, counter, temp, 0, (int) polyLength);
					counter += polyLength;

					poly = byteToArray(temp, (int) (polyLength / intDimension));
				}
			}
			v.setElementAt(new TSSPolynomial(f, p, poly), i);
		}

		return v;
	}
}
