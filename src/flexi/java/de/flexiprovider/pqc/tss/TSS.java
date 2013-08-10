package de.flexiprovider.pqc.tss;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Vector;

import codec.asn1.ASN1Exception;
import de.flexiprovider.api.MessageDigest;
import de.flexiprovider.api.Signature;
import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.api.exceptions.InvalidKeyException;
import de.flexiprovider.api.exceptions.SignatureException;
import de.flexiprovider.api.keys.PrivateKey;
import de.flexiprovider.api.keys.PublicKey;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.math.IntegerFunctions;

public abstract class TSS extends Signature {

	/**
	 * TSS with RIPEMD128
	 * 
	 */
	public static class RIPEMD128 extends TSS {
		/**
		 * Constructor.
		 */
		public RIPEMD128() {
			super(new de.flexiprovider.core.md.RIPEMD128());
		}
	}

	/**
	 * TSS with RIPEMD160
	 * 
	 */
	public static class RIPEMD160 extends TSS {
		/**
		 * Constructor.
		 */
		public RIPEMD160() {
			super(new de.flexiprovider.core.md.RIPEMD160());
		}
	}

	/**
	 * TSS with RIPEMD256
	 * 
	 */
	public static class RIPEMD256 extends TSS {
		/**
		 * Constructor.
		 */
		public RIPEMD256() {
			super(new de.flexiprovider.core.md.RIPEMD256());
		}
	}

	/**
	 * TSS with RIPEMD320
	 * 
	 */
	public static class RIPEMD320 extends TSS {
		/**
		 * Constructor.
		 */
		public RIPEMD320() {
			super(new de.flexiprovider.core.md.RIPEMD320());
		}
	}

	/**
	 * TSS with SHA1
	 * 
	 */
	public static class SHA1 extends TSS {
		/**
		 * Constructor.
		 */
		public SHA1() {
			super(new de.flexiprovider.core.md.SHA1());
		}
	}

	/**
	 * TSS with SHA224
	 * 
	 */
	public static class SHA224 extends TSS {
		/**
		 * Constructor.
		 */
		public SHA224() {
			super(new de.flexiprovider.core.md.SHA224());
		}
	}

	/**
	 * TSS with SHA256
	 * 
	 */
	public static class SHA256 extends TSS {
		/**
		 * Constructor.
		 */
		public SHA256() {
			super(new de.flexiprovider.core.md.SHA256());
		}
	}

	/**
	 * TSS with SHA384
	 * 
	 */
	public static class SHA384 extends TSS {
		/**
		 * Constructor.
		 */
		public SHA384() {
			super(new de.flexiprovider.core.md.SHA384());
		}
	}

	/**
	 * TSS with SHA512
	 * 
	 */
	public static class SHA512 extends TSS {
		/**
		 * Constructor.
		 */
		public SHA512() {
			super(new de.flexiprovider.core.md.SHA512());
		}
	}

	public static int floor2Log(int i) {
		int counter = 0;
		while (i >= 1024) {
			i = i >>> 10;
			counter += 10;
		}
		while (i != 1) {
			i = i >>> 1;
			counter += 1;
		}

		return counter;
	}

	private TSSPrivateKey privKey = null;

	private TSSPublicKey pubKey = null;

	/**
	 * Used to generate random gfps
	 */
	private TSSPolynomial refGfp;

	private byte[] message = null;

	/**
	 * the message-digest used for the hashfunction
	 */
	protected MessageDigest messageDigest = null;

	/**
	 * the hash-function described in the document
	 */
	protected TSSHashFunction hashFunction = null;

	// dimension: integer that is a power of two
	protected int n = 0;

	// 3 log(n)
	protected int m = 0;

	// prime
	protected long p = 0;

	protected TSS(MessageDigest md) {
		messageDigest = md;
	}

	/**
	 * Adds two Vectors of {@link TSSPolynomial} by adding the Polynomials in
	 * each Vector. The Polynomial in Vector @a at position i is added to the
	 * Polynomial in Vector @b at position i. If one Vector is larger than the
	 * other, then the excess Polynomials of the larger Vector are not modified
	 * (Zero Poly added).
	 * 
	 * @param a
	 *            Vector containing {@link TSSPolynomial}
	 * @param b
	 *            Vector containing {@link TSSPolynomial}
	 * @return The Vector of the added Polynomials
	 */
	public Vector addGFPVector(Vector a, Vector b) {
		Vector result = new Vector();
		int aSize = a.size();
		int bSize = b.size();
		int max = Math.max(aSize, bSize);
		int min = Math.min(aSize, bSize);

		result.setSize(max);

		if (bSize > aSize) {
			Vector c = a;
			a = b;
			b = c;
		}

		for (int i = max - 1; i >= 0; i--) {
			if (i >= min) {
				result.setElementAt((a.elementAt(i)), i);
			} else {
				result.setElementAt((((TSSPolynomial) a.elementAt(i))
						.add((TSSPolynomial) b.elementAt(i))), i);
			}
		}

		return result;
	}

	public long[] binary2ternary(byte[] binary) {
		SecureRandom rand = null;
		try {
			rand = SecureRandom.getInstance("SHA1PRNG");
			rand.setSeed(binary);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		// if (binary.length < n) {
		// return null;
		// }
		long[] ternary = new long[n];
		// System.arraycopy(binary, 0, ternary, 0, n);
		for (int i = n - 1; i >= 0; i--) {
			ternary[i] = rand.nextInt(3) - 1;
		}

		return ternary;
	}

	/**
	 * Checks if all of the values in the given array are smaller or equal the
	 * defined boundary
	 * 
	 * @param arr
	 * @param bound
	 * @return
	 */
	public boolean checkBound(long[] arr, long bound) {
		for (int i = arr.length - 1; i >= 0; i--) {
			if (Math.abs(arr[i]) > bound) {
				System.out.println(arr[i] + " > " + bound + " at index " + i);
				return false;
			}
		}
		return true;
	}

	/**
	 * Checks if all of the values in the contained arrays are smaller or equal
	 * bound
	 * 
	 * @param v
	 *            a Vector containing long[]
	 * @param bound
	 * @return
	 */
	public boolean checkBound(Vector v, long bound) {
		for (int i = v.size() - 1; i >= 0; i--) {
			if (!checkBound(((TSSPolynomial) v.elementAt(i)).getCompressed(),
					bound)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * returns a Vector of {@link TSSPolynomial}s
	 * 
	 * @param limit
	 *            the limit of the elements in the polynomials (eg: 2 to receive
	 *            polynomials with the values {-1, 0, 1})
	 * @param amount
	 *            the amount of Polynomials in the vector
	 * @return the Vector of Polynomials
	 */
	public Vector getPolyVector(int limit, int amount) {
		Vector result = new Vector();
		result.setSize(amount);

		for (int i = amount - 1; i >= 0; i--) {
			result.setElementAt(refGfp.generatePoly(limit, true), i);
		}

		return result;
	}

	public void initSign(PrivateKey privKey,
			de.flexiprovider.api.SecureRandom random)
			throws InvalidKeyException {
		if (privKey.getClass().equals(TSSPrivateKey.class)) {
			this.privKey = (TSSPrivateKey) privKey;
		} else {
			throw new InvalidKeyException();
		}
	}

	public void initVerify(PublicKey pubKey) throws InvalidKeyException {
		if (pubKey.getClass().equals(TSSPublicKey.class)) {
			this.pubKey = (TSSPublicKey) pubKey;
		} else {
			throw new InvalidKeyException();
		}
	}

	/**
	 * returns a pseudo random {@link TSSPolynomial} with values <= |1|
	 * 
	 * @param u
	 *            the input byte array for which to create the pseudo random
	 *            output
	 * @return a pseudo random {@link TSSPolynomial}
	 * @throws IOException
	 * @throws ASN1Exception
	 */
	public TSSPolynomial oracle(TSSPolynomial gfp, byte[] b) {
		byte[] gfpArr = null;

		try {
			gfpArr = gfp.getEncoded();
		} catch (ASN1Exception asn1Ex) {
			// TODO
			asn1Ex.printStackTrace();
		} catch (IOException ioEx) {
			// TODO
			ioEx.printStackTrace();
		}

		byte[] combined = new byte[gfpArr.length + b.length];

		System.arraycopy(gfpArr, 0, combined, 0, gfpArr.length);
		System.arraycopy(b, 0, combined, gfpArr.length, b.length);

		combined = messageDigest.digest(combined);

		long[] encoded = binary2ternary(combined);

		return new TSSPolynomial(gfp.getF(), p, encoded);
	}

	private byte[] parse2TSSByte(Vector v, TSSPolynomial gfp) {
		int size = v.size() + 1;
		v.setSize(size);

		v.setElementAt(gfp, size - 1);

		return new TSSVectorSerial(v).getArrayRepresentation();
	}

	private Vector parse2TSSVector(byte[] b) {
		TSSVectorSerial gv = new TSSVectorSerial(b);

		Vector v = gv.getVectorRepresentation();

		// Inversion of parse2TSSByte
		// TODO special case, need to include in method where both e and z are
		// required

		return v;
	}

	public void setParameters(AlgorithmParameterSpec params)
			throws InvalidAlgorithmParameterException {
		if (!(params instanceof TSSParameterSpec)) {
			throw new InvalidAlgorithmParameterException("Wrong Parameterclass");
		}

		if (params == null) {
			throw new InvalidAlgorithmParameterException(
					"Params cannot be null");
		}

		TSSParameterSpec paramSpec = (TSSParameterSpec) params;

		hashFunction = paramSpec.getHFunction();

		n = paramSpec.getN();
		m = paramSpec.getM();
		p = paramSpec.getP();
		refGfp = paramSpec.getRefGFP();

		int[] f = new int[n + 1];
		f[n] = 1;
		f[0] = 1;
	}

	public byte[] sign() {

		message = messageDigest.digest();
		messageDigest.reset();

		int yBound;
		int gBound;

		yBound = m
				* (int) Math.floor(IntegerFunctions.intRoot(IntegerFunctions
						.pow(n, 3), 2)
						* IntegerFunctions.floatLog(n));
		gBound = yBound - (int) (Math.sqrt(n) * IntegerFunctions.floatLog(n));

		int counter = 0;

		TSSPolynomial e;
		Vector z;

		Vector y;
		System.out.println("Attempting to find match...");
		do {
			Date time1 = new Date();
			y = getPolyVector(yBound + 1, m);
			e = oracle(hashFunction.calculatHash(y), message);

			z = addGFPVector(e.multiply(privKey.getKey()), y);
			if (counter > 1000) {
				try {
					throw new Exception("could not generate a valid Signature");
				} catch (Exception ex) {
					ex.printStackTrace();
					break;
				}
			}
			counter += 1;
			Date time2 = new Date();
			System.out.println("Signature generation took "
					+ (time2.getTime() - time1.getTime()) + " ms.");
		} while (!checkBound(z, gBound));
		System.out.println("Match found.");
		// System.out.println("*******************************************");
		// System.out.println("h(e*s) = ");
		// hashFunction.calculatHash(e.multiply(privKey.getKey())).print();
		// System.out.println("h(s) * e  = ");
		// hashFunction.calculatHash(privKey.getKey()).multiply(e).print();
		// System.out.println("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");
		//
		// globalBrutal = hashFunction.calculatHash(y);
		//
		// System.out.println("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
		// hashFunction.calculatHash(addGFPVector(privKey.getKey(), y)).print();
		// hashFunction.calculatHash(privKey.getKey()).add(hashFunction.calculatHash(y)).print();
		// System.out.println("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");
		return parse2TSSByte(z, e);
	}

	public void update(byte input) throws SignatureException {
		messageDigest.update(input);
	}

	public void update(byte[] input, int inOff, int inLen)
			throws SignatureException {
		messageDigest.update(input, inOff, inLen);
	}

	public boolean verify(byte[] signature) throws SignatureException {

		byte[] mue = message;
		Vector z;
		long gBound;
		long yBound;

		z = new TSSVectorSerial(signature).getVectorRepresentation();

		int vSize = z.size() - 1;

		TSSPolynomial e = (TSSPolynomial) z.elementAt(vSize);
		z.removeElementAt(vSize);
		z.setSize(vSize);

		yBound = m
				* (long) Math.floor(IntegerFunctions.intRoot(IntegerFunctions
						.pow(n, 3), 2)
						* IntegerFunctions.floatLog(n));

		gBound = yBound - (long) (Math.sqrt(n) * IntegerFunctions.floatLog(n));
		e.print();

		if (checkBound(z, gBound)) {
			if (e.equals(oracle(hashFunction.calculatHash(z).subtract(
					pubKey.getS().multiply(e)), mue))) {
				return true;
			} else {
				return false;
			}
		} else {
			return false;
		}
	}
}
