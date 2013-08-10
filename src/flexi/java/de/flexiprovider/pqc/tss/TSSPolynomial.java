package de.flexiprovider.pqc.tss;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Vector;

import codec.asn1.ASN1Exception;
import codec.asn1.ASN1Integer;
import codec.asn1.ASN1Sequence;
import codec.asn1.ASN1SequenceOf;
import codec.asn1.DERDecoder;
import codec.asn1.DEREncoder;
import de.flexiprovider.api.Registry;
import de.flexiprovider.api.SecureRandom;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.util.ASN1Tools;

/**
 * An Element of this class represents a Polynomial within a GFP Ring Structure.
 * <p>
 * The Structure is defined by the modulo Function and the large "prime" p. This
 * Class has methods for multiplying, adding and reducing Polynomials.
 * <p>
 * This Class has been developed mainly for the LMOTS Signature scheme, so the
 * available methods may not be a complete Implementation of the methods that
 * may be required or expected on Ring Arithmetic and some of the implemented
 * Methods are intended only for use of the LMOTS Signature scheme. Such as the
 * ability to create random Polynomials within this Ring Structure with a custom
 * modulo limit or Multiplication of a Polynomial with a Vector of Polynomials.
 */
public class TSSPolynomial {

	private long[] f;
	private long[] poly;
	private int degree;

	private long p;

	private SecureRandom generator;

	/**
	 * Constructor for decoding a previously encoded {@link GFPPolynomial} using
	 * the getEncoded() method
	 * 
	 * @param encoded
	 *            the byte array containing the encoded {@link GFPPolynomial}
	 * @throws IOException
	 * @throws ASN1Exception
	 */
	public TSSPolynomial(byte[] encoded) throws ASN1Exception, IOException {
		ByteArrayInputStream in = new ByteArrayInputStream(encoded);
		DERDecoder decoder = new DERDecoder(in);
		ASN1Sequence gfpSequence = new ASN1Sequence(3);
		gfpSequence.add(new ASN1SequenceOf(ASN1Integer.class));
		gfpSequence.add(new ASN1Integer());
		gfpSequence.add(new ASN1SequenceOf(ASN1Integer.class));
		gfpSequence.decode(decoder);
		in.close();

		ASN1SequenceOf asn1F = (ASN1SequenceOf) gfpSequence.get(0);
		ASN1Integer asn1P = (ASN1Integer) gfpSequence.get(1);
		ASN1SequenceOf asn1Poly = (ASN1SequenceOf) gfpSequence.get(2);

		long[] poly = new long[asn1Poly.size()];
		for (int i = poly.length - 1; i >= 0; i--) {
			poly[i] = ASN1Tools.getFlexiBigInt((ASN1Integer) asn1Poly.get(i))
					.intValue();
		}
		this.poly = poly;
		long[] f = new long[asn1F.size()];
		degree = f.length - 1;
		for (int i = degree; i >= 0; i--) {
			f[i] = ASN1Tools.getFlexiBigInt((ASN1Integer) asn1F.get(i))
					.intValue();
		}
		this.f = f;
		p = ASN1Tools.getFlexiBigInt(asn1P).intValue();

		generator = Registry.getSecureRandom();
	}

	/**
	 * Standard Constructor for generating a new GFPPolynomial
	 * 
	 * @param f
	 *            the modulo Polynomial of the Ring
	 * @param p
	 *            the modulo "prime" of the Ring
	 * @param poly
	 *            the Polynomial an long array, most significant entry is right
	 */
	public TSSPolynomial(long[] f, long p, long[] poly) {
		this.f = f;
		degree = f.length - 1;
		this.p = p;
		this.poly = reduce(poly);
		generator = Registry.getSecureRandom();
	}

	/**
	 * Special Constructor without a Polynomial parameter but with a Secure
	 * Random generator. This Constructor can only be used for methods which do
	 * not require a Polynomial to be present, such as generatePoly()
	 * 
	 * @param f
	 *            the modulo Polynomial of the Ring
	 * @param p
	 *            the modulo "prime" of the Ring
	 * @param gen
	 *            a predefined secure Random Number Generator
	 */
	public TSSPolynomial(long[] f, long p, SecureRandom gen) {
		this.f = f;
		degree = f.length - 1;
		this.p = p;
		generator = Registry.getSecureRandom();
	}

	/**
	 * adds the given Polynomial to this Polynomial and returns the result
	 * 
	 * @param gfp
	 *            the Polynomial to be added
	 * @return the Addition of the two Polynomials
	 */
	public TSSPolynomial add(TSSPolynomial gfp) {
		if (!paramEqual(gfp)) {
			return null;
		}
		long[] b = gfp.getPoly();
		long[] a = poly;
		if (a.length < b.length) {
			a = b;
			b = poly;
		}

		long[] result = new long[a.length];

		for (int i = a.length - 1; i >= 0; i--) {
			result[i] = a[i];
			if (i < b.length) {
				result[i] = (result[i] + b[i]) % p;
			}
		}

		return new TSSPolynomial(f, p, reduce(result));
	}

	/**
	 * Adds the supplied Polynomial to this Polynomial and sets this Polynomial
	 * as the result
	 * 
	 * @param gfp
	 *            the Polynomial to be added
	 */
	public void addToThis(TSSPolynomial gfp) {
		poly = add(gfp).getPoly();
	}

	public boolean arrEqual(long[] arr1, long[] arr2) {
		if (arr1.length != arr2.length) {
			return false;
		} else {
			for (int i = arr1.length - 1; i >= 0; i--) {
				if (arr1[i] != arr2[i]) {
					return false;
				}
			}
			return true;
		}
	}

	private long[] compress(long[] a) {
		return compress(a, p);
	}

	private long[] compress(long[] a, long p) {
		for (int i = a.length; i > 0; i--) {
			if (a[i - 1] > p / 2) {
				a[i - 1] -= p;
			}
		}
		return a;
	}

	public boolean equals(Object obj) {
		if (obj.getClass().equals(getClass())) {
			TSSPolynomial gfp = (TSSPolynomial) obj;
			return p == gfp.getP() && arrEqual(f, gfp.getF())
					&& arrEqual(mod(getPoly()), mod(gfp.getPoly()));
		}
		return false;
	}

	/**
	 * also compares SecureRandom, but since that class has no default equals
	 * operator, this method is useless (for now)
	 * 
	 * @param gfp
	 *            the {@link TSSPolynomial} to compare to.
	 * @return
	 */
	private boolean fullEquals(TSSPolynomial gfp) {
		return p == gfp.getP() && arrEqual(f, gfp.getF())
				&& arrEqual(poly, gfp.getPoly())
				&& generator.equals(gfp.getRandomizer());
	}

	/**
	 * Generates a random Polynomial, complying to the specification of this
	 * Ring
	 * 
	 * @return the randomly generated Polynomial
	 */
	public TSSPolynomial generatePoly() {
		return generatePoly(0);
	}

	/**
	 * Generates a random Polynomial with the specified limit, denoting the
	 * maximum Value of entries in this Polynomial.
	 * 
	 * @param limit
	 *            the limit to be used for modulo in the generated Polynomial.
	 *            Only used if the supplied number is lower than p, otherwise p
	 *            is used.
	 * @return the randomly generated Polynomial
	 */
	public TSSPolynomial generatePoly(long limit) {
		return generatePoly(limit, false);
	}

	public TSSPolynomial generatePoly(long limit, boolean negative) {
		if (limit == 0 || limit > p) {
			limit = p;
		}
		long[] resPoly = new long[degree];
		for (int i = degree; i > 0; i--) {
			if (negative) {
				resPoly[i - 1] = nextLong(limit * 2 - 1);
			} else {
				resPoly[i - 1] = nextLong(limit);
			}
		}
		if (negative) {
			return new TSSPolynomial(f, p, compress(resPoly, limit * 2 - 1));
		} else {
			return new TSSPolynomial(f, p, reduceZeros(resPoly));
		}
	}

	/**
	 * Subtracts p from every entry in this polynomial with a value greater p/2.
	 * <p>
	 * This Function is used for calculating the correct Norm of a Polynomial,
	 * since the Norm uses the absolute Value for determining the Maximum
	 * 
	 * @return the compressed polynomial
	 */
	public long[] getCompressed() {
		return compress(poly);
	}

	public byte[] getEncoded() throws ASN1Exception, IOException {
		// TODO use ASN.1
		ASN1Sequence gfpSequence = new ASN1Sequence(3);
		ASN1Integer asn1P = ASN1Tools.createInteger(new FlexiBigInt("" + p));
		ASN1SequenceOf asn1Poly = new ASN1SequenceOf(ASN1Integer.class);
		ASN1SequenceOf asn1F = new ASN1SequenceOf(ASN1Integer.class);
		for (int i = 0; i < poly.length; i++) {
			asn1Poly
					.add(ASN1Tools.createInteger(new FlexiBigInt("" + poly[i])));
		}
		for (int i = 0; i < f.length; i++) {
			asn1F.add(ASN1Tools.createInteger(new FlexiBigInt("" + f[i])));
		}
		gfpSequence.add(asn1F);
		gfpSequence.add(asn1P);
		gfpSequence.add(asn1Poly);

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		gfpSequence.encode(new DEREncoder(baos));
		byte[] res = baos.toByteArray();
		baos.flush();
		baos.close();

		return res;
	}

	public long[] getF() {
		return f;
	}

	public long getP() {
		return p;
	}

	/**
	 * 
	 * @return The (reduced) Polynomial as an long array
	 */
	public long[] getPoly() {
		return poly;
	}

	public SecureRandom getRandomizer() {
		return generator;
	}

	private long[] mod(long[] poly) {
		for (int i = poly.length; i > 0; i--) {
			if (poly[i - 1] < 0) {
				poly[i - 1] = poly[i - 1] % p + p;
			} else {
				poly[i - 1] = poly[i - 1] % p;
			}
		}
		return poly;
	}

	private long modMultiply(long p, long q) {
		return 0;
	}

	/**
	 * multiplies the given Polynomial to this Polynomial and returns the Result
	 * 
	 * @param gfp
	 *            the Polynomial to be multiplied
	 * @return the Product of the two Polynomials
	 */
	public TSSPolynomial multiply(TSSPolynomial gfp) {
		if (!paramEqual(gfp)) {
			return null;
		}
		long[] a = poly;
		long[] z = gfp.getPoly();
		int degree = a.length + z.length - 1;
		long[] result = new long[degree];
		// Arrays.fill(result, 0);

		a = compress(a);
		z = compress(z);

		for (int i = a.length - 1; i >= 0; i--) {
			for (int j = z.length - 1; j >= 0; j--) {
				result[i + j] = (result[i + j] + (a[i] * z[j])) % p;
				// FlexiBigInt l = new FlexiBigInt("" + a[i]);
				// FlexiBigInt k = new FlexiBigInt("" + z[j]);
				// k = l.multiply(k).mod(new FlexiBigInt("" + p));
				// result[i + j] = (k.longValue() + result[i + j]) % p;
			}
		}
		result = mod(result);
		return new TSSPolynomial(f, p, reduce(result));
	}

	/**
	 * multiplies this Polynomial with a Vector of Polynomials and returns the
	 * Result
	 * <p>
	 * Multiplication with a Vector is designed as follows:
	 * <p>
	 * Vector � = (a1, a2, ... , am), Polynomial p � * p = (a1*p, a2*p, ...
	 * , am * p)
	 * 
	 * @param k
	 *            the Vector of Polynomials to be multiplied
	 * @return the Vector of the Product
	 */
	public Vector multiply(Vector k) {
		Vector result = new Vector();
		result.setSize(k.size());

		for (int i = k.size() - 1; i >= 0; i--) {
			TSSPolynomial next = (TSSPolynomial) k.elementAt(i);
			result.setElementAt(multiply(next), i);

		}

		return result;
	}

	/**
	 * Multiplies the given Polynomial to this Polynomial and sets this
	 * Polynomial to the Result
	 * 
	 * @param gfp
	 *            the Polynomial to be multiplied
	 */
	public void multiplyToThis(TSSPolynomial gfp) {
		poly = multiply(gfp).getPoly();
	}

	private long nextLong(long limit) {
		if (limit > Integer.MAX_VALUE) {
			return (generator.nextInt() * generator.nextInt()) % limit;
		} else {
			return generator.nextInt((int) limit);
		}
	}

	public boolean paramEqual(TSSPolynomial gfp) {
		return p == gfp.getP() && arrEqual(f, gfp.getF());
	}

	public void print() {
		System.out.println("printing GFP");
		System.out.println("p: " + getP());
		System.out.println("f: " + printPoly(getF()));
		System.out.println("poly: " + printPoly(getPoly()));
	}

	private String printPoly(long[] arr) {
		String result = "{";
		for (int i = arr.length - 1; i > 0; i--) {
			result += arr[i] + ", ";
		}
		result += arr[0] + "}";
		return result;
	}

	/**
	 * This Methods reduces a Polynomial in long array representation, with the
	 * most significant value rightmost. This means that the supplied Polynomial
	 * will be calculated modulo the Ring Polynomial f and the remainder is
	 * returned.
	 * 
	 * @param z
	 *            The supplied Polynomial to be reduced
	 * @return the remainder of the reduced Polynomial
	 */
	private long[] reduce(long[] z) {
		z = reduceZeros(mod(z));
		int gradZ = z.length;
		int gradN = f.length;
		if (gradZ < gradN) {
			return z;
		} else {
			z = compress(z);
			for (int i = gradZ - gradN; i >= 0; i--) {
				long quotient = z[i + gradN - 1];
				z[i] = (z[i] - quotient) % p;
				z[i + gradN - 1] = (z[i + gradN - 1] - quotient) % p;
			}
			long[] remainder = new long[gradN - 1];
			System.arraycopy(z, 0, remainder, 0, remainder.length);
			return reduceZeros(mod(remainder));
		}
	}

	private long[] reduceZeros(long[] z) {
		int zSize = z.length;
		for (int i = z.length; i > 0; i--) {
			if (z[i - 1] == 0) {
				zSize--;
			} else {
				break;
			}
		}

		if (zSize == z.length) {
			return z;
		} else {
			long[] newZ = new long[zSize];
			System.arraycopy(z, 0, newZ, 0, zSize);
			return newZ;
		}
	}

	public TSSPolynomial subtract(TSSPolynomial gfp) {
		if (!paramEqual(gfp)) {
			return null;
		}
		long[] b = gfp.getPoly();
		long[] a = poly;

		long[] result = new long[Math.max(a.length, b.length)];

		for (int i = result.length - 1; i >= 0; i--) {
			if (i < b.length && i < a.length) {
				result[i] = (a[i] - b[i]) % p;
			} else if (i < b.length) {
				result[i] = -b[i];
			} else {
				result[i] = a[i];
			}
		}

		return new TSSPolynomial(f, p, reduce(result));
	}

	public void subtractFromThis(TSSPolynomial gfp) {
		poly = subtract(gfp).getPoly();
	}
}
