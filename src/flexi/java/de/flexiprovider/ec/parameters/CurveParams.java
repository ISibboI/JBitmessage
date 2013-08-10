package de.flexiprovider.ec.parameters;

import codec.asn1.ASN1ObjectIdentifier;
import de.flexiprovider.api.parameters.AlgorithmParameterSpec;
import de.flexiprovider.common.exceptions.NoSuchBasisException;
import de.flexiprovider.common.exceptions.PolynomialIsNotIrreducibleException;
import de.flexiprovider.common.math.FlexiBigInt;
import de.flexiprovider.common.math.ellipticcurves.EllipticCurve;
import de.flexiprovider.common.math.ellipticcurves.EllipticCurveGF2n;
import de.flexiprovider.common.math.ellipticcurves.EllipticCurveGFP;
import de.flexiprovider.common.math.ellipticcurves.Point;
import de.flexiprovider.common.math.ellipticcurves.PointGF2n;
import de.flexiprovider.common.math.ellipticcurves.PointGFP;
import de.flexiprovider.common.math.finitefields.GF2Polynomial;
import de.flexiprovider.common.math.finitefields.GF2nElement;
import de.flexiprovider.common.math.finitefields.GF2nONBElement;
import de.flexiprovider.common.math.finitefields.GF2nONBField;
import de.flexiprovider.common.math.finitefields.GF2nPolynomialElement;
import de.flexiprovider.common.math.finitefields.GF2nPolynomialField;
import de.flexiprovider.common.math.finitefields.GFPElement;
import de.flexiprovider.common.util.ByteUtils;
import de.flexiprovider.common.util.StringUtils;

/**
 * This class implements EC Domain Parameters as specified in the standard <a
 * href = "http://grouper.ieee.org/groups/1363/P1363">IEEE P1363-D8</a>.
 * 
 * @author Birgit Henhapl
 * @author Martin Döring
 */
public abstract class CurveParams implements AlgorithmParameterSpec {

    /**
     * OID
     */
    private ASN1ObjectIdentifier oid;

    /**
     * size of the underlying field (either a prime or a power of two)
     */
    FlexiBigInt q;

    /**
     * elliptic curve E
     */
    EllipticCurve E;

    /**
     * basepoint G
     */
    Point g;

    /**
     * order r of basepoint G
     */
    private FlexiBigInt r;

    /**
     * cofactor k
     */
    private int k;

    /**
     * Construct new curve parameters from the given Strings.
     * 
     * @param r
     *                order r of basepoint G
     * @param k
     *                cofactor k
     */
    protected CurveParams(String r, String k) {
	String s = StringUtils.filterSpaces(r);
	this.r = new FlexiBigInt(s, 16);
	s = StringUtils.filterSpaces(k);
	this.k = Integer.valueOf(s, 16).intValue();
    }

    /**
     * Construct new curve parameters from the given Strings.
     * 
     * @param oid
     *                OID of the curve parameters
     * @param r
     *                order r of basepoint G
     * @param k
     *                cofactor k
     */
    protected CurveParams(String oid, String r, String k) {
	this.oid = new ASN1ObjectIdentifier(oid);
	String s = StringUtils.filterSpaces(r);
	this.r = new FlexiBigInt(s, 16);
	s = StringUtils.filterSpaces(k);
	this.k = Integer.valueOf(s, 16).intValue();
    }

    /**
     * Construct new curve parameters from the given parameters.
     * 
     * @param g
     *                basepoint G
     * @param r
     *                order r of basepoint G
     * @param k
     *                cofactor k
     */
    protected CurveParams(Point g, FlexiBigInt r, int k) {
	this.g = g;
	E = g.getE();
	q = E.getQ();
	this.r = r;
	this.k = k;
    }

    /**
     * @return the OID of the curve parameters
     */
    public ASN1ObjectIdentifier getOID() {
	return oid;
    }

    /**
     * @return the size of the underlying field
     */
    public FlexiBigInt getQ() {
	return q;
    }

    /**
     * @return the elliptic curve <tt>E</tt>
     */
    public EllipticCurve getE() {
	return E;
    }

    /**
     * @return a copy of the basepoint <tt>G</tt>
     */
    public Point getG() {
	return (Point) g.clone();
    }

    /**
     * @return the order <tt>r</tt> of basepoint <tt>G</tt>
     */
    public FlexiBigInt getR() {
	return r;
    }

    /**
     * @return the cofactor <tt>k</tt>
     */
    public int getK() {
	return k;
    }

    /**
     * @return the hash code of these curve parameters
     */
    public int hashCode() {

    	int oidHashCode = 0;
		int qHashCode = 0;
		int eHashCode = 0;
		int gHashCode = 0;
		int rHashCode = 0;
		int kHashCode = k;

		if (oid != null) {
			oidHashCode = oid.hashCode();
		}
		if (q != null) {
			qHashCode = q.hashCode();
		}
		if (E != null) {
			eHashCode = E.hashCode();
		}
		if (g != null) {
			gHashCode = g.hashCode();
		}
		if (r != null) {
			rHashCode = r.hashCode();
		}
		
		return oidHashCode + qHashCode + eHashCode + gHashCode + rHashCode + kHashCode;
		
	}

    /**
     * Compare these parameters with another object.
     * 
     * @param other
     *                the other object
     * @return the result of the comparison
     */
    public boolean equals(Object other) {
	if ((other == null) || !(other instanceof CurveParams)) {
	    return false;
	}
	CurveParams otherParams = (CurveParams) other;
	return oid.equals(otherParams.oid) && q.equals(otherParams.q)
		&& E.equals(otherParams.E) && g.equals(otherParams.g)
		&& r.equals(otherParams.r) && (k == otherParams.k);
    }

    /**
     * Inner class for representing prime curve parameters.
     */
    public static class CurveParamsGFP extends CurveParams {

	/**
	 * Construct new curve parameters from the given Strings.
	 * 
	 * @param a
	 *                curve coefficient a
	 * @param b
	 *                curve coefficient b
	 * @param p
	 *                prime characteristic p
	 * @param g
	 *                basepoint G
	 * @param r
	 *                order r of basepoint G
	 * @param k
	 *                cofactor k
	 */
	public CurveParamsGFP(String a, String b, String p, String g, String r,
		String k) {
	    super(r, k);

	    String s = StringUtils.filterSpaces(p);
	    this.q = new FlexiBigInt(s, 16);

	    s = StringUtils.filterSpaces(a);
	    byte[] encA = ByteUtils.fromHexString(s);
	    GFPElement mA = new GFPElement(encA, this.q);

	    s = StringUtils.filterSpaces(b);
	    byte[] encB = ByteUtils.fromHexString(s);
	    GFPElement mB = new GFPElement(encB, this.q);

	    E = new EllipticCurveGFP(mA, mB, this.q);

	    s = StringUtils.filterSpaces(g);
	    byte[] encG = ByteUtils.fromHexString(s);
	    this.g = new PointGFP(encG, (EllipticCurveGFP) E);
	}

	/**
	 * Construct new curve parameters from the given parameters.
	 * 
	 * @param g
	 *                basepoint G
	 * @param r
	 *                order r of basepoint G
	 * @param k
	 *                cofactor k
	 */
	public CurveParamsGFP(PointGFP g, FlexiBigInt r, int k) {
	    super(g, r, k);
	}

	/**
	 * Construct new curve parameters from the given Strings.
	 * 
	 * @param oid
	 *                OID of the curve parameters (can be <tt>null</tt>)
	 * @param a
	 *                curve coefficient a
	 * @param b
	 *                curve coefficient b
	 * @param p
	 *                prime characteristic p
	 * @param g
	 *                basepoint G
	 * @param r
	 *                order r of basepoint G
	 * @param k
	 *                cofactor k
	 */
	protected CurveParamsGFP(String oid, String a, String b, String p,
		String g, String r, String k) {
	    super(oid, r, k);

	    String s = StringUtils.filterSpaces(p);
	    this.q = new FlexiBigInt(s, 16);

	    s = StringUtils.filterSpaces(a);
	    byte[] encA = ByteUtils.fromHexString(s);
	    GFPElement mA = new GFPElement(encA, this.q);

	    s = StringUtils.filterSpaces(b);
	    byte[] encB = ByteUtils.fromHexString(s);
	    GFPElement mB = new GFPElement(encB, this.q);

	    E = new EllipticCurveGFP(mA, mB, this.q);

	    s = StringUtils.filterSpaces(g);
	    byte[] encG = ByteUtils.fromHexString(s);
	    this.g = new PointGFP(encG, (EllipticCurveGFP) E);
	}

	/**
	 * @return the hash code of these curve parameters
	 */
	public int hashCode() {
	    return super.hashCode();
	}

	/**
	 * Compare these parameters with another object.
	 * 
	 * @param other
	 *                the other object
	 * @return the result of the comparison
	 */
	public boolean equals(Object other) {
	    if ((other == null) || !(other instanceof CurveParamsGFP)) {
		return false;
	    }
	    return super.equals(other);
	}
    }

    /**
     * Inner class for representing char 2 curve parameters.
     */
    public abstract static class CurveParamsGF2n extends CurveParams {

	/**
	 * extension degree n
	 */
	protected int n;

	/**
	 * Construct new curve parameters from the given Strings.
	 * 
	 * @param r
	 *                order r of basepoint G
	 * @param n
	 *                extension degree n
	 * @param k
	 *                cofactor k
	 */
	protected CurveParamsGF2n(String r, String n, String k) {
	    super(r, k);
	    String s = StringUtils.filterSpaces(n);
	    this.n = Integer.valueOf(s).intValue();
	    this.q = FlexiBigInt.ONE.shiftLeft(this.n);
	}

	/**
	 * Construct new curve parameters from the given Strings.
	 * 
	 * @param oid
	 *                OID of the curve parameters
	 * @param r
	 *                order r of basepoint G
	 * @param n
	 *                extension degree n
	 * @param k
	 *                cofactor k
	 */
	protected CurveParamsGF2n(String oid, String r, String n, String k) {
	    super(oid, r, k);
	    String s = StringUtils.filterSpaces(n);
	    this.n = Integer.valueOf(s).intValue();
	    this.q = FlexiBigInt.ONE.shiftLeft(this.n);
	}

	/**
	 * Construct new curve parameters from the given parameters.
	 * 
	 * @param g
	 *                basepoint G
	 * @param r
	 *                order r of basepoint G
	 * @param n
	 *                extension degree n
	 * @param k
	 *                cofactor k
	 */
	protected CurveParamsGF2n(PointGF2n g, FlexiBigInt r, int n, int k) {
	    super(g, r, k);
	    this.n = n;
	}

	/**
	 * @return the extension degree <tt>n</tt> of the underlying field
	 */
	public int getN() {
	    return n;
	}

	/**
	 * @return the hash code of these curve parameters
	 */
	public int hashCode() {
	    return super.hashCode() + n;
	}

	/**
	 * Compare these parameters with another object.
	 * 
	 * @param other
	 *                the other object
	 * @return the result of the comparison
	 */
	public boolean equals(Object other) {
	    if ((other == null) || !(other instanceof CurveParamsGF2n)) {
		return false;
	    }
	    CurveParamsGF2n otherParams = (CurveParamsGF2n) other;
	    return super.equals(other) && (n == otherParams.n);
	}
    }

    /**
     * Inner class for representing char 2 curve parameters.
     */
    public static class CurveParamsGF2nONB extends CurveParamsGF2n {

	/**
	 * Construct new curve parameters from the given Strings.
	 * 
	 * @param a
	 *                curve coefficient a
	 * @param b
	 *                curve coefficient b
	 * @param g
	 *                basepoint G
	 * @param r
	 *                order r of basepoint G
	 * @param n
	 *                extension degree n
	 * @param k
	 *                cofactor k
	 */
	public CurveParamsGF2nONB(String a, String b, String g, String r,
		String n, String k) {
	    super(r, n, k);

	    String s = StringUtils.filterSpaces(a);
	    byte[] encA = ByteUtils.fromHexString(s);

	    s = StringUtils.filterSpaces(b);
	    byte[] encB = ByteUtils.fromHexString(s);

	    s = StringUtils.filterSpaces(g);
	    byte[] encG = ByteUtils.fromHexString(s);

	    // field
	    GF2nONBField onbField = new GF2nONBField(getN());

	    // curve coefficients
	    GF2nElement mA = new GF2nONBElement(onbField, encA);
	    GF2nElement mB = new GF2nONBElement(onbField, encB);

	    // curve
	    E = new EllipticCurveGF2n(mA, mB, getN());

	    // basepoint
	    this.g = new PointGF2n(encG, (EllipticCurveGF2n) E);
	}

	/**
	 * Construct new curve parameters from the given parameters.
	 * 
	 * @param g
	 *                basepoint G
	 * @param r
	 *                order r of basepoint G
	 * @param n
	 *                extension degree n
	 * @param k
	 *                cofactor k
	 */
	public CurveParamsGF2nONB(PointGF2n g, FlexiBigInt r, int n, int k) {
	    super(g, r, n, k);
	}

	/**
	 * Construct new curve parameters from the given Strings.
	 * 
	 * @param oid
	 *                OID of the curve parameters
	 * @param a
	 *                curve coefficient a
	 * @param b
	 *                curve coefficient b
	 * @param g
	 *                basepoint G
	 * @param r
	 *                order r of basepoint G
	 * @param n
	 *                extension degree n
	 * @param k
	 *                cofactor k
	 */
	protected CurveParamsGF2nONB(String oid, String a, String b, String g,
		String r, String n, String k) {
	    super(oid, r, n, k);

	    String s = StringUtils.filterSpaces(a);
	    byte[] encA = ByteUtils.fromHexString(s);

	    s = StringUtils.filterSpaces(b);
	    byte[] encB = ByteUtils.fromHexString(s);

	    s = StringUtils.filterSpaces(g);
	    byte[] encG = ByteUtils.fromHexString(s);

	    // field
	    GF2nONBField onbField = new GF2nONBField(getN());

	    // curve coefficients
	    GF2nElement mA = new GF2nONBElement(onbField, encA);
	    GF2nElement mB = new GF2nONBElement(onbField, encB);

	    // curve
	    E = new EllipticCurveGF2n(mA, mB, getN());

	    // basepoint
	    this.g = new PointGF2n(encG, (EllipticCurveGF2n) E);
	}

	/**
	 * @return the hash code of these curve parameters
	 */
	public int hashCode() {
	    return super.hashCode();
	}

	/**
	 * Compare these parameters with another object.
	 * 
	 * @param other
	 *                the other object
	 * @return the result of the comparison
	 */
	public boolean equals(Object other) {
	    if ((other == null) || !(other instanceof CurveParamsGF2nONB)) {
		return false;
	    }
	    return super.equals(other);
	}
    }

    /**
     * Inner class for representing char 2 trinomial curve parameters.
     */
    public static class CurveParamsGF2nTrinomial extends CurveParamsGF2n {
	/**
	 * trinomial coefficient
	 */
	private int tc;

	/**
	 * Construct new curve parameters from the given Strings.
	 * 
	 * @param a
	 *                curve coefficient a
	 * @param b
	 *                curve coefficient b
	 * @param g
	 *                basepoint G
	 * @param r
	 *                order r of basepoint G
	 * @param n
	 *                extension degree n
	 * @param k
	 *                cofactor k
	 * @param tc
	 *                trinomial coefficient
	 */
	public CurveParamsGF2nTrinomial(String a, String b, String g, String r,
		String n, String k, String tc) {
	    super(r, n, k);

	    String s = StringUtils.filterSpaces(a);
	    byte[] encA = ByteUtils.fromHexString(s);

	    s = StringUtils.filterSpaces(b);
	    byte[] encB = ByteUtils.fromHexString(s);

	    s = StringUtils.filterSpaces(g);
	    byte[] encG = ByteUtils.fromHexString(s);

	    this.tc = Integer.valueOf(tc).intValue();

	    // construct the field polynomial
	    int[] polBytes = new int[(this.n + 31) >> 5];
	    // set the trinomial coefficients
	    polBytes[0] = 1;
	    polBytes[this.tc >> 5] |= 1 << (this.tc & 0x1f);
	    polBytes[this.n >> 5] |= 1 << (this.n & 0x1f);

	    // field polynomial and field
	    GF2Polynomial fieldPoly = new GF2Polynomial(this.n + 1, polBytes);
	    GF2nPolynomialField polyField = null;
	    try {
		polyField = new GF2nPolynomialField(this.n, fieldPoly);
	    } catch (PolynomialIsNotIrreducibleException pinie) {
		throw new NoSuchBasisException(pinie.getMessage());
	    }

	    // curve coefficients
	    GF2nElement mA = new GF2nPolynomialElement(polyField, encA);
	    GF2nElement mB = new GF2nPolynomialElement(polyField, encB);

	    // curve
	    E = new EllipticCurveGF2n(mA, mB, this.n);

	    // basepoint
	    this.g = new PointGF2n(encG, (EllipticCurveGF2n) E);
	}

	/**
	 * Construct new curve parameters from the given parameters.
	 * 
	 * @param g
	 *                basepoint G
	 * @param r
	 *                order r of basepoint G
	 * @param n
	 *                extension degree n
	 * @param k
	 *                cofactor k
	 * @param tc
	 *                trinomial coefficient
	 */
	public CurveParamsGF2nTrinomial(PointGF2n g, FlexiBigInt r, int n,
		int k, int tc) {
	    super(g, r, n, k);
	    this.tc = tc;
	}

	/**
	 * Construct new curve parameters from the given Strings.
	 * 
	 * @param oid
	 *                OID of the curve parameters
	 * @param a
	 *                curve coefficient a
	 * @param b
	 *                curve coefficient b
	 * @param g
	 *                basepoint G
	 * @param r
	 *                order r of basepoint G
	 * @param n
	 *                extension degree n
	 * @param k
	 *                cofactor k
	 * @param tc
	 *                trinomial coefficient
	 */
	protected CurveParamsGF2nTrinomial(String oid, String a, String b,
		String g, String r, String n, String k, String tc) {
	    super(oid, r, n, k);

	    String s = StringUtils.filterSpaces(a);
	    byte[] encA = ByteUtils.fromHexString(s);

	    s = StringUtils.filterSpaces(b);
	    byte[] encB = ByteUtils.fromHexString(s);

	    s = StringUtils.filterSpaces(g);
	    byte[] encG = ByteUtils.fromHexString(s);

	    this.tc = Integer.valueOf(tc).intValue();

	    // construct the field polynomial
	    int[] polBytes = new int[(this.n + 31) >> 5];
	    // set the trinomial coefficients
	    polBytes[0] = 1;
	    polBytes[this.tc >> 5] |= 1 << (this.tc & 0x1f);
	    polBytes[this.n >> 5] |= 1 << (this.n & 0x1f);

	    // field polynomial and field
	    GF2Polynomial fieldPoly = new GF2Polynomial(this.n + 1, polBytes);
	    GF2nPolynomialField polyField = null;
	    try {
		polyField = new GF2nPolynomialField(this.n, fieldPoly);
	    } catch (PolynomialIsNotIrreducibleException pinie) {
		throw new NoSuchBasisException(pinie.getMessage());
	    }

	    // curve coefficients
	    GF2nElement mA = new GF2nPolynomialElement(polyField, encA);
	    GF2nElement mB = new GF2nPolynomialElement(polyField, encB);

	    // curve
	    E = new EllipticCurveGF2n(mA, mB, this.n);

	    // basepoint
	    this.g = new PointGF2n(encG, (EllipticCurveGF2n) E);
	}

	/**
	 * @return the trinomial coefficient
	 */
	public int getTC() {
	    return tc;
	}

	/**
	 * @return the hash code of these curve parameters
	 */
	public int hashCode() {
	    return super.hashCode() + tc;
	}

	/**
	 * Compare these parameters with another object.
	 * 
	 * @param other
	 *                the other object
	 * @return the result of the comparison
	 */
	public boolean equals(Object other) {
	    if ((other == null) || !(other instanceof CurveParamsGF2nTrinomial)) {
		return false;
	    }
	    CurveParamsGF2nTrinomial otherParams = (CurveParamsGF2nTrinomial) other;
	    return super.equals(other) && (tc == otherParams.tc);
	}
    }

    /**
     * Inner class for representing char 2 pentanomial curve parameters.
     */
    public static class CurveParamsGF2nPentanomial extends CurveParamsGF2n {
	/**
	 * first pentanomial coefficient
	 */
	private int pc1;

	/**
	 * second pentanomial coefficient
	 */
	private int pc2;

	/**
	 * third pentanomial coefficient
	 */
	private int pc3;

	/**
	 * Construct new curve parameters from the given Strings.
	 * 
	 * @param a
	 *                curve coefficient a
	 * @param b
	 *                curve coefficient b
	 * @param g
	 *                basepoint G
	 * @param r
	 *                order r of basepoint G
	 * @param n
	 *                extension degree n
	 * @param k
	 *                cofactor k
	 * @param pc1
	 *                first pentanomial coefficient
	 * @param pc2
	 *                second pentanomial coefficient
	 * @param pc3
	 *                third pentanomial coefficient
	 */
	public CurveParamsGF2nPentanomial(String a, String b, String g,
		String r, String n, String k, String pc1, String pc2, String pc3) {
	    super(r, n, k);

	    String s = StringUtils.filterSpaces(a);
	    byte[] encA = ByteUtils.fromHexString(s);

	    s = StringUtils.filterSpaces(b);
	    byte[] encB = ByteUtils.fromHexString(s);

	    s = StringUtils.filterSpaces(g);
	    byte[] encG = ByteUtils.fromHexString(s);

	    this.pc1 = Integer.valueOf(pc1).intValue();
	    this.pc2 = Integer.valueOf(pc2).intValue();
	    this.pc3 = Integer.valueOf(pc3).intValue();

	    // construct the field polynomial
	    int[] polBytes = new int[(this.n + 31) >> 5];
	    // set the pentanomial coefficients
	    polBytes[0] = 1;
	    polBytes[this.pc1 >> 5] |= 1 << (this.pc1 & 0x1f);
	    polBytes[this.pc2 >> 5] |= 1 << (this.pc2 & 0x1f);
	    polBytes[this.pc3 >> 5] |= 1 << (this.pc3 & 0x1f);
	    polBytes[this.n >> 5] |= 1 << (this.n & 0x1f);

	    // field polynomial and field
	    GF2Polynomial fieldPoly = new GF2Polynomial(this.n + 1, polBytes);
	    GF2nPolynomialField polyField = null;
	    try {
		polyField = new GF2nPolynomialField(this.n, fieldPoly);
	    } catch (PolynomialIsNotIrreducibleException pinie) {
		throw new NoSuchBasisException(pinie.getMessage());
	    }

	    // curve coefficients
	    GF2nElement mA = new GF2nPolynomialElement(polyField, encA);
	    GF2nElement mB = new GF2nPolynomialElement(polyField, encB);

	    // curve
	    E = new EllipticCurveGF2n(mA, mB, this.n);

	    // basepoint
	    this.g = new PointGF2n(encG, (EllipticCurveGF2n) E);
	}

	/**
	 * Construct new curve parameters from the given parameters.
	 * 
	 * @param g
	 *                basepoint G
	 * @param r
	 *                order r of basepoint G
	 * @param n
	 *                extension degree n
	 * @param k
	 *                cofactor k
	 * @param pc1
	 *                first pentanomial coefficient
	 * @param pc2
	 *                second pentanomial coefficient
	 * @param pc3
	 *                third pentanomial coefficient
	 */
	public CurveParamsGF2nPentanomial(PointGF2n g, FlexiBigInt r, int n,
		int k, int pc1, int pc2, int pc3) {
	    super(g, r, n, k);
	    this.pc1 = pc1;
	    this.pc2 = pc2;
	    this.pc3 = pc3;
	}

	/**
	 * Construct new curve parameters from the given Strings.
	 * 
	 * @param oid
	 *                OID of the curve parameters
	 * @param a
	 *                curve coefficient a
	 * @param b
	 *                curve coefficient b
	 * @param g
	 *                basepoint G
	 * @param r
	 *                order r of basepoint G
	 * @param n
	 *                extension degree n
	 * @param k
	 *                cofactor k
	 * @param pc1
	 *                first pentanomial coefficient
	 * @param pc2
	 *                second pentanomial coefficient
	 * @param pc3
	 *                third pentanomial coefficient
	 */
	protected CurveParamsGF2nPentanomial(String oid, String a, String b,
		String g, String r, String n, String k, String pc1, String pc2,
		String pc3) {
	    super(oid, r, n, k);

	    String s = StringUtils.filterSpaces(a);
	    byte[] encA = ByteUtils.fromHexString(s);

	    s = StringUtils.filterSpaces(b);
	    byte[] encB = ByteUtils.fromHexString(s);

	    s = StringUtils.filterSpaces(g);
	    byte[] encG = ByteUtils.fromHexString(s);

	    this.pc1 = Integer.valueOf(pc1).intValue();
	    this.pc2 = Integer.valueOf(pc2).intValue();
	    this.pc3 = Integer.valueOf(pc3).intValue();

	    // construct the field polynomial
	    int[] polBytes = new int[(this.n + 31) >> 5];
	    // set the pentanomial coefficients
	    polBytes[0] = 1;
	    polBytes[this.pc1 >> 5] |= 1 << (this.pc1 & 0x1f);
	    polBytes[this.pc2 >> 5] |= 1 << (this.pc2 & 0x1f);
	    polBytes[this.pc3 >> 5] |= 1 << (this.pc3 & 0x1f);
	    polBytes[this.n >> 5] |= 1 << (this.n & 0x1f);

	    // field polynomial and field
	    GF2Polynomial fieldPoly = new GF2Polynomial(this.n + 1, polBytes);
	    GF2nPolynomialField polyField = null;
	    try {
		polyField = new GF2nPolynomialField(this.n, fieldPoly);
	    } catch (PolynomialIsNotIrreducibleException pinie) {
		throw new NoSuchBasisException(pinie.getMessage());
	    }

	    // curve coefficients
	    GF2nElement mA = new GF2nPolynomialElement(polyField, encA);
	    GF2nElement mB = new GF2nPolynomialElement(polyField, encB);

	    // curve
	    E = new EllipticCurveGF2n(mA, mB, this.n);

	    // basepoint
	    this.g = new PointGF2n(encG, (EllipticCurveGF2n) E);
	}

	/**
	 * @return the first pentanomial coefficient
	 */
	public int getPC1() {
	    return pc1;
	}

	/**
	 * @return the second pentanomial coefficient
	 */
	public int getPC2() {
	    return pc2;
	}

	/**
	 * @return the third pentanomial coefficient
	 */
	public int getPC3() {
	    return pc3;
	}

	/**
	 * @return the hash code of these curve parameters
	 */
	public int hashCode() {
	    return super.hashCode() + pc1 + pc2 + pc3;
	}

	/**
	 * Compare these parameters with another object.
	 * 
	 * @param other
	 *                the other object
	 * @return the result of the comparison
	 */
	public boolean equals(Object other) {
	    if ((other == null)
		    || !(other instanceof CurveParamsGF2nPentanomial)) {
		return false;
	    }
	    CurveParamsGF2nPentanomial otherParams = (CurveParamsGF2nPentanomial) other;
	    return super.equals(other) && (pc1 == otherParams.pc1)
		    && (pc2 == otherParams.pc2) && (pc3 == otherParams.pc3);
	}
    }

}
