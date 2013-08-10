/*
 * Copyright (c) 1998-2008 by The FlexiProvider Group,
 *                            Technische Universitaet Darmstadt 
 *
 * For conditions of usage and distribution please refer to the
 * file COPYING in the root directory of this package.
 *
 */
package de.flexiprovider.ec.parameters;

import java.util.Hashtable;

import de.flexiprovider.api.exceptions.InvalidAlgorithmParameterException;
import de.flexiprovider.ec.parameters.CurveParams.CurveParamsGF2nPentanomial;
import de.flexiprovider.ec.parameters.CurveParams.CurveParamsGF2nTrinomial;
import de.flexiprovider.ec.parameters.CurveParams.CurveParamsGFP;

/**
 * This class contains some approved EC domain parameters for Elliptic Curve
 * Cryptography. They can be used with the ECDSA, ECNR, ECDH, and ECIES
 * algorithms.
 * <p>
 * The following EC domain parameters are supported here:
 * <p>
 * <b>Prime parameters</b>
 * <p>
 * <ul type="square">
 * <li>Parameters from ANSI X9.62
 * <ul type="circle">
 * <li>1.2.840.10045.3.1.1 (prime192v1)</li>
 * <li>1.2.840.10045.3.1.2 (prime192v2)</li>
 * <li>1.2.840.10045.3.1.3 (prime192v3)</li>
 * <li>1.2.840.10045.3.1.4 (prime239v1)</li>
 * <li>1.2.840.10045.3.1.5 (prime239v2)</li>
 * <li>1.2.840.10045.3.1.6 (prime239v3)</li>
 * <li>1.2.840.10045.3.1.7 (prime256v1)</li>
 * </ul>
 * </li>
 * <li>Parameters from SEC 2
 * <ul type="circle">
 * <li>1.3.132.0.6 (secp112r1)</li>
 * <li>1.3.132.0.7 (secp112r2)</li>
 * <li>1.3.132.0.28 (secp128r1)</li>
 * <li>1.3.132.0.29 (secp128r2)</li>
 * <li>1.3.132.0.9 (secp160k1)</li>
 * <li>1.3.132.0.8 (secp160r1)</li>
 * <li>1.3.132.0.30 (secp160r2)</li>
 * <li>1.3.132.0.31 (secp192k1)</li>
 * <li>1.3.132.0.32 (secp224k1)</li>
 * <li>1.3.132.0.33 (secp224r1)</li>
 * <li>1.3.132.0.10 (secp256k1)</li>
 * <li>1.3.132.0.34 (secp384r1)</li>
 * <li>1.3.132.0.35 (secp521r1)</li>
 * </ul>
 * </li>
 * <li>Parameters defined by the ECC brainpool
 * <ul type="circle">
 * <li>1.3.36.3.3.2.8.1.1.1 (brainpoolP160r1)</li>
 * <li>1.3.36.3.3.2.8.1.1.3 (brainpoolP192r1)</li>
 * <li>1.3.36.3.3.2.8.1.1.5 (brainpoolP224r1)</li>
 * <li>1.3.36.3.3.2.8.1.1.7 (brainpoolP256r1)</li>
 * <li>1.3.36.3.3.2.8.1.1.9 (brainpoolP320r1)</li>
 * <li>1.3.36.3.3.2.8.1.1.11 (brainpoolP384r1)</li>
 * <li>1.3.36.3.3.2.8.1.1.13 (brainpoolP512r1)</li>
 * </ul>
 * </li>
 * <li>Parameters defined by the CDC group
 * <ul type="circle">
 * <li>1.3.6.1.4.1.8301.3.1.2.9.0.1</li>
 * <li>1.3.6.1.4.1.8301.3.1.2.9.0.2</li>
 * <li>1.3.6.1.4.1.8301.3.1.2.9.0.3</li>
 * <li>1.3.6.1.4.1.8301.3.1.2.9.0.4</li>
 * <li>1.3.6.1.4.1.8301.3.1.2.9.0.5</li>
 * <li>1.3.6.1.4.1.8301.3.1.2.9.0.6</li>
 * <li>1.3.6.1.4.1.8301.3.1.2.9.0.7</li>
 * <li>1.3.6.1.4.1.8301.3.1.2.9.0.8</li>
 * <li>1.3.6.1.4.1.8301.3.1.2.9.0.9</li>
 * <li>1.3.6.1.4.1.8301.3.1.2.9.0.10</li>
 * <li>1.3.6.1.4.1.8301.3.1.2.9.0.11</li>
 * <li>1.3.6.1.4.1.8301.3.1.2.9.0.12</li>
 * <li>1.3.6.1.4.1.8301.3.1.2.9.0.13</li>
 * <li>1.3.6.1.4.1.8301.3.1.2.9.0.14</li>
 * <li>1.3.6.1.4.1.8301.3.1.2.9.0.15</li>
 * <li>1.3.6.1.4.1.8301.3.1.2.9.0.16</li>
 * <li>1.3.6.1.4.1.8301.3.1.2.9.0.17</li>
 * <li>1.3.6.1.4.1.8301.3.1.2.9.0.18</li>
 * <li>1.3.6.1.4.1.8301.3.1.2.9.0.19</li>
 * <li>1.3.6.1.4.1.8301.3.1.2.9.0.20</li>
 * <li>1.3.6.1.4.1.8301.3.1.2.9.0.21</li>
 * <li>1.3.6.1.4.1.8301.3.1.2.9.0.22</li>
 * <li>1.3.6.1.4.1.8301.3.1.2.9.0.23</li>
 * <li>1.3.6.1.4.1.8301.3.1.2.9.0.24</li>
 * <li>1.3.6.1.4.1.8301.3.1.2.9.0.25 (NIST curve)</li>
 * <li>1.3.6.1.4.1.8301.3.1.2.9.0.26</li>
 * <li>1.3.6.1.4.1.8301.3.1.2.9.0.27</li>
 * <li>1.3.6.1.4.1.8301.3.1.2.9.0.28</li>
 * <li>1.3.6.1.4.1.8301.3.1.2.9.0.29</li>
 * <li>1.3.6.1.4.1.8301.3.1.2.9.0.30</li>
 * <li>1.3.6.1.4.1.8301.3.1.2.9.0.31</li>
 * <li>1.3.6.1.4.1.8301.3.1.2.9.0.32</li>
 * <li>1.3.6.1.4.1.8301.3.1.2.9.0.33</li>
 * <li>1.3.6.1.4.1.8301.3.1.2.9.0.34</li>
 * <li>1.3.6.1.4.1.8301.3.1.2.9.0.35</li>
 * <li>1.3.6.1.4.1.8301.3.1.2.9.0.36</li>
 * <li>1.3.6.1.4.1.8301.3.1.2.9.0.37</li>
 * <li>1.3.6.1.4.1.8301.3.1.2.9.0.38 (NIST curve)</li>
 * </ul>
 * </li>
 * </ul>
 * <p>
 * <b>Characteristic two parameters</b>
 * <p>
 * <ul type="square">
 * <li>Parameters from ANSI X9.62
 * <ul type="circle">
 * <li>1.2.840.10045.3.0.1 (c2pnb163v1)</li>
 * <li>1.2.840.10045.3.0.2 (c2pnb163v2)</li>
 * <li>1.2.840.10045.3.0.3 (c2pnb163v3)</li>
 * <li>1.2.840.10045.3.0.5 (c2tnb191v1)</li>
 * <li>1.2.840.10045.3.0.6 (c2tnb191v2)</li>
 * <li>1.2.840.10045.3.0.7 (c2tnb191v3)</li>
 * <li>1.2.840.10045.3.0.10 (c2pnb208w1)</li>
 * <li>1.2.840.10045.3.0.11 (c2tnb239v1)</li>
 * <li>1.2.840.10045.3.0.12 (c2tnb239v2)</li>
 * <li>1.2.840.10045.3.0.13 (c2tnb239v3)</li>
 * <li>1.2.840.10045.3.0.16 (c2pnb272w1)</li>
 * <li>1.2.840.10045.3.0.18 (c2tnb359v1)</li>
 * <li>1.2.840.10045.3.0.19 (c2pnb368w1)</li>
 * <li>1.2.840.10045.3.0.20 (c2tnb431r1)</li>
 * </ul>
 * </li>
 * </ul>
 * <p>
 * <b>NOTE:</b>
 * <p>
 * The OIDs with prefix 1.3.6.1.4.1.8301.3.1.2 are OIDs of parameters defined by
 * the CDC group, except for the OIDs 1.3.6.1.4.1.8301.3.1.2.9.0.25 and
 * 1.3.6.1.4.1.8301.3.1.2.9.0.38, which are OIDs of NIST defined parameters.
 * <p>
 * The CDC defined OIDs are supported only by the FlexiECProvider.
 */
public final class CurveRegistry {

    /*-------------------------------------------------
     * PRIME CURVES
     -------------------------------------------------*/

    /* ANSI X9.62 */

    public static final class Prime192v1 extends CurveParamsGFP {

	/**
	 * The OID of prime192v1.
	 */
	public static final String OID = "1.2.840.10045.3.1.1";

	public Prime192v1() {
	    super(OID,
	    // curve coefficient a
		    "ffffffff ffffffff ffffffff fffffffe ffffffff fffffffc",
		    // curve coefficient b
		    "64210519 e59c80e7 0fa7e9ab 72243049 feb8deec c146b9b1",
		    // prime p
		    "ffffffff ffffffff ffffffff fffffffe ffffffff ffffffff",
		    // basepoint G
		    "03 188da80e b03090f6 7cbf20eb 43a18800 f4ff0afd 82ff1012",
		    // order of basepoint G
		    "ffffffff ffffffff ffffffff 99def836 146bc9b1 b4d22831",
		    // cofactor k
		    "01");
	}
    }

    public static final class Prime192v2 extends CurveParamsGFP {

	/**
	 * The OID of prime192v2.
	 */
	public static final String OID = "1.2.840.10045.3.1.2";

	public Prime192v2() {
	    super(OID,
	    // curve coefficient a
		    "ffffffff ffffffff ffffffff ffffffFe ffffffff ffffffFC",
		    // curve coefficient b
		    "cc22d6df b95c6b25 e49c0d63 64a4e598 0c393aa2 1668d953",
		    // prime p
		    "ffffffff ffffffff ffffffff fffffffe ffffffff ffffffff",
		    // basepoint G
		    "03 eea2bae7 e1497842 f2de7769 cfe9c989 c072ad69 6f48034a",
		    // order of basepoint G
		    "ffffffff ffffffff fffffffe 5fb1a724 dc804186 48d8dd31",
		    // cofactor k
		    "01");
	}
    }

    public static final class Prime192v3 extends CurveParamsGFP {

	/**
	 * The OID of prime192v3.
	 */
	public static final String OID = "1.2.840.10045.3.1.3";

	public Prime192v3() {
	    super(OID,
	    // curve coefficient a
		    "ffffffff ffffffff ffffffff fffffffe ffffffff fffffffc",
		    // curve coefficient b
		    "22123dc2 395a05ca a7423dae ccc94760 a7d46225 6bd56916",
		    // prime p
		    "ffffffff ffffffff ffffffff fffffffe ffffffff ffffffff",
		    // basepoint G
		    "02 7d297781 00c65a1d a1783716 588dce2b 8b4aee8e 228f1896",
		    // order of basepoint G
		    "ffffffff ffffffff ffffffff 7a62d031 c83f4294 f640ec13",
		    // cofactor k
		    "01");
	}
    }

    public static final class Prime239v1 extends CurveParamsGFP {

	/**
	 * The OID of prime239v1.
	 */
	public static final String OID = "1.2.840.10045.3.1.4";

	public Prime239v1() {
	    super(
		    OID,
		    // curve coefficient a
		    "7ffF ffffffff ffffffff ffff7fff ffffffff 80000000 00007fff fffffffc",
		    // curve coefficient b
		    "6B01 6C3BDCF1 8941D0D6 54921475 CA71A9DB 2FB27D1D 37796185 C2942C0A",
		    // prime p
		    "7fff ffffffff ffffffff ffff7fff ffffffff 80000000 00007fff ffffffff",
		    // basepoint G
		    "020ffA 963CDCA8 816CCC33 B8642BED F905C3D3 58573D3F 27FBBD3B 3CB9AAAF",
		    // order of basepoint G
		    "7fff ffffffff ffffffff ffff7fff ff9e5e9a 9f5d9071 fbd15226 88909d0b",
		    // cofactor k
		    "01");
	}
    }

    public static final class Prime239v2 extends CurveParamsGFP {

	/**
	 * The OID of prime239v2.
	 */
	public static final String OID = "1.2.840.10045.3.1.5";

	public Prime239v2() {
	    super(
		    OID,
		    // curve coefficient a
		    "7ffF ffffffff ffffffff ffff7ffF ffffffff 80000000 00007ffF ffffffFC",
		    // curve coefficient b
		    "617F AB683257 6CBBFED5 0D99F024 9C3FEE58 B94BA003 8C7AE84C 8C832F2C",
		    // prime p
		    "7fff ffffffff ffffffff ffff7fff ffffffff 80000000 00007fff ffffffff",
		    // basepoint G
		    "0238AF 09D98727 705120C9 21BB5E9E 26296A3C DCF2F357 57A0EAFD 87B830E7",
		    // order of basepoint G
		    "7fff ffffffff ffffffff ffff8000 00CFA7E8 594377D4 14C03821 BC582063",
		    // cofactor k
		    "01");
	}
    }

    public static final class Prime239v3 extends CurveParamsGFP {

	/**
	 * The OID of prime239v3.
	 */
	public static final String OID = "1.2.840.10045.3.1.6";

	public Prime239v3() {
	    super(
		    OID,
		    // curve coefficient a
		    "7ffF ffffffff ffffffff ffff7ffF ffffffff 80000000 00007ffF ffffffFC",
		    // curve coefficient b
		    "2557 05FA2A30 6654B1F4 CB03D6A7 50A30C25 0102D498 8717D9BA 15AB6D3E",
		    // prime p
		    "7fff ffffffff ffffffff ffff7fff ffffffff 80000000 00007fff ffffffff",
		    // basepoint G
		    "036768 AE8E18BB 92CFCF00 5C949AA2 C6D94853 D0E660BB F854B1C9 505FE95A",
		    // order of basepoint G
		    "7fff ffffffff ffffffff ffff7fff ff975DEB 41B3A605 7C3C4321 46526551",
		    // cofactor k
		    "01");
	}
    }

    public static final class Prime256v1 extends CurveParamsGFP {

	/**
	 * The OID of prime256v1.
	 */
	public static final String OID = "1.2.840.10045.3.1.7";

	public Prime256v1() {
	    super(
		    OID,
		    // curve coefficient a
		    "ffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff ffffffFC",
		    // curve coefficient b
		    "5AC635D8 AA3A93E7 B3EBBD55 769886BC 651D06B0 CC53B0F6 3BCE3C3E 27D2604B",
		    // prime p
		    "ffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff ffffffff",
		    // basepoint G
		    "03 6B17D1F2 E12C4247 F8BCE6E5 63A440F2 77037D81 2DEB33A0 F4A13945 D898C296",
		    // order of basepoint G
		    "ffffffff 00000000 ffffffff ffffffff BCE6FAAD A7179E84 F3B9CAC2 FC632551",
		    // cofactor k
		    "01");
	}
    }

    /* SEC 2 */

    public static final class Secp112r1 extends CurveParamsGFP {

	/**
	 * The OID of secp112r1.
	 */
	public static final String OID = "1.3.132.0.6";

	public Secp112r1() {
	    super(
		    OID,
		    // curve coefficient a
		    "DB7C 2ABF62E3 5E668076 BEAD2088",
		    // curve coefficient b
		    "659E F8BA0439 16EEDE89 11702B22",
		    // prime p
		    "db7c 2abf62e3 5e668076 bead208b",
		    // basepoint G
		    "04 09487239 995A5EE7 6B55F9C2 F098A89C E5AF8724 C0A23E0E 0ff77500",
		    // order of basepoint G
		    "DB7C 2ABF62E3 5E7628DF AC6561C5",
		    // cofactor k
		    "01");
	}
    }

    public static final class Secp112r2 extends CurveParamsGFP {

	/**
	 * The OID of secp112r2.
	 */
	public static final String OID = "1.3.132.0.7";

	public Secp112r2() {
	    super(
		    OID,
		    // curve coefficient a
		    "6127 C24C05F3 8A0AAAF6 5C0EF02C",
		    // curve coefficient b
		    "51DE F1815DB5 ED74FCC3 4C85D709",
		    // prime p
		    "db7c 2abf62e3 5e668076 bead208b",
		    // basepoint G
		    "04 4BA30AB5 E892B4E1 649DD092 8643ADCD 46F5882E 3747DEF3 6E956E97",
		    // order of basepoint G
		    "36DF 0AAFD8B8 D7597CA1 0520D04B",
		    // cofactor k
		    "01");
	}
    }

    public static final class Secp128r1 extends CurveParamsGFP {

	/**
	 * The OID of secp128r1.
	 */
	public static final String OID = "1.3.132.0.28";

	public Secp128r1() {
	    super(
		    OID,
		    // curve coefficient a
		    "ffffffFD ffffffff ffffffff ffffffFC",
		    // curve coefficient b
		    "E87579C1 1079F43D D824993C 2CEE5ED3",
		    // prime p
		    "fffffffd ffffffff ffffffff ffffffff",
		    // basepoint G
		    "04 161ff752 8B899B2D 0C28607C A52C5B86 CF5AC839 5BAFEB13 C02DA292 DDED7A83",
		    // order of basepoint G
		    "ffffffFE 00000000 75A30D1B 9038A115",
		    // cofactor k
		    "01");
	}
    }

    public static final class Secp128r2 extends CurveParamsGFP {

	/**
	 * The OID of secp128r2.
	 */
	public static final String OID = "1.3.132.0.29";

	public Secp128r2() {
	    super(
		    OID,
		    // curve coefficient a
		    "D6031998 D1B3BBFE BF59CC9B Bff9AEE1",
		    // curve coefficient b
		    "5EEEFCA3 80D02919 DC2C6558 BB6D8A5D",
		    // prime p
		    "fffffffd ffffffff ffffffff ffffffff",
		    // basepoint G
		    "04 7B6AA5D8 5E572983 E6FB32A7 CDEBC140 27B6916A 894D3AEE 7106FE80 5FC34B44",
		    // order of basepoint G
		    "3ffffffF 7ffffffF BE002472 0613B5A3",
		    // cofactor k
		    "04");
	}
    }

    public static final class Secp160k1 extends CurveParamsGFP {

	/**
	 * The OID of secp160k1.
	 */
	public static final String OID = "1.3.132.0.9";

	public Secp160k1() {
	    super(
		    OID,
		    // curve coefficient a
		    "00000000 00000000 00000000 00000000 00000000",
		    // curve coefficient b
		    "00000000 00000000 00000000 00000000 00000007",
		    // prime p
		    "ffffffff ffffffff ffffffff fffffffe ffffac73",
		    // basepoint G
		    "04 3B4C382C E37AA192 A4019E76 3036F4F5 DD4D7EBB 938CF935 318FDCED 6BC28286 531733C3 F03C4FEE",
		    // order of basepoint G
		    "01 00000000 00000000 0001B8FA 16DFAB9A CA16B6B3",
		    // cofactor k
		    "01");
	}
    }

    public static final class Secp160r1 extends CurveParamsGFP {

	/**
	 * The OID of secp160r1.
	 */
	public static final String OID = "1.3.132.0.8";

	public Secp160r1() {
	    super(OID,
	    // curve coefficient a
		    "ffffffff ffffffff ffffffff ffffffff 7ffffffC",
		    // curve coefficient b
		    "1C97BEFC 54BD7A8B 65ACF89F 81D4D4AD C565FA45",
		    // prime p
		    "ffffffff ffffffff ffffffff ffffffff 7fffffff",
		    // basepoint G
		    "02 4A96B568 8EF57328 46646989 68C38BB9 13CBFC82",
		    // order of basepoint G
		    "01 00000000 00000000 0001F4C8 F927AED3 CA752257",
		    // cofactor k
		    "01");
	}
    }

    public static final class Secp160r2 extends CurveParamsGFP {

	/**
	 * The OID of secp160r2.
	 */
	public static final String OID = "1.3.132.0.30";

	public Secp160r2() {
	    super(
		    OID,
		    // curve coefficient a
		    "ffffffff ffffffff ffffffff ffffffFE ffffAC70",
		    // curve coefficient b
		    "B4E134D3 FB59EB8B AB572749 04664D5A F50388BA",
		    // prime p
		    "ffffffff ffffffff ffffffff fffffffe ffffac73",
		    // basepoint G
		    "04 52DCB034 293A117E 1F4ff11B 30F7199D 3144CE6D FEAffEF2 E331F296 E071FA0D F9982CFE A7D43F2E",
		    // order of basepoint G
		    "01 00000000 00000000 0000351E E786A818 F3A1A16B",
		    // cofactor k
		    "01");
	}
    }

    public static final class Secp192k1 extends CurveParamsGFP {

	/**
	 * The OID of secp192k1.
	 */
	public static final String OID = "1.3.132.0.31";

	public Secp192k1() {
	    super(
		    OID,
		    // curve coefficient a
		    "00000000 00000000 00000000 00000000 00000000 00000000",
		    // curve coefficient b
		    "00000000 00000000 00000000 00000000 00000000 00000003",
		    // prime p
		    "ffffffff ffffffff ffffffff ffffffff fffffffe ffffee37",
		    // basepoint G
		    "04 DB4ff10E C057E9AE 26B07D02 80B7F434 1DA5D1B1 EAE06C7D 9B2F2F6D 9C5628A7 844163D0 15BE8634 4082AA88 D95E2F9D",
		    // order of basepoint G
		    "ffffffff ffffffff ffffffFE 26F2FC17 0F69466A 74DEFD8D",
		    // cofactor k
		    "01");
	}
    }

    public static final class Secp224k1 extends CurveParamsGFP {

	/**
	 * The OID of secp224k1.
	 */
	public static final String OID = "1.3.132.0.32";

	public Secp224k1() {
	    super(
		    OID,
		    // curve coefficient a
		    "00000000 00000000 00000000 00000000 00000000 00000000 00000000",
		    // curve coefficient b
		    "00000000 00000000 00000000 00000000 00000000 00000000 00000005",
		    // prime p
		    "ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe ffffe56d",
		    // basepoint G
		    "04 A1455B33 4DF099DF 30FC28A1 69A467E9 E47075A9 0F7E650E B6B7A45C 7E089FED 7FBA3442 82CAFBD6 F7E319F7 C0B0BD59 E2CA4BDB 556D61A5",
		    // order of basepoint G
		    "01 00000000 00000000 00000000 0001DCE8 D2EC6184 CAF0A971 769FB1F7",
		    // cofactor k
		    "01");
	}
    }

    public static final class Secp224r1 extends CurveParamsGFP {

	/**
	 * The OID of secp224r1.
	 */
	public static final String OID = "1.3.132.0.33";

	public Secp224r1() {
	    super(
		    OID,
		    // curve coefficient a
		    "ffffffff ffffffff ffffffff ffffffFE ffffffff ffffffff ffffffFE",
		    // curve coefficient b
		    "B4050A85 0C04B3AB F5413256 5044B0B7 D7BFD8BA 270B3943 2355ffB4",
		    // prime p
		    "ffffffff ffffffff ffffffff ffffffff 00000000 00000000 00000001",
		    // basepoint G
		    "04 B70E0CBD 6BB4BF7F 321390B9 4A03C1D3 56C21122 343280D6 115C1D21 BD376388 B5F723FB 4C22DFE6 CD4375A0 5A074764 44D58199 85007E34",
		    // order of basepoint G
		    "ffffffff ffffffff ffffffff ffff16A2 E0B8F03E 13DD2945 5C5C2A3D",
		    // cofactor k
		    "01");
	}
    }

    public static final class Secp256k1 extends CurveParamsGFP {

	/**
	 * The OID of secp256k1.
	 */
	public static final String OID = "1.3.132.0.10";

	public Secp256k1() {
	    super(
		    OID,
		    // curve coefficient a
		    "00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000",
		    // curve coefficient b
		    "00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000007",
		    // prime p
		    "ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe fffffc2f",
		    // basepoint G
		    "04 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798 483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8",
		    // order of basepoint G
		    "ffffffff ffffffff ffffffff ffffffFE BAAEDCE6 AF48A03B BFD25E8C D0364141",
		    // cofactor k
		    "01");
	}
    }

    public static final class Secp384r1 extends CurveParamsGFP {

	/**
	 * The OID of secp384r1.
	 */
	public static final String OID = "1.3.132.0.34";

	public Secp384r1() {
	    super(
		    OID,
		    // curve coefficient a
		    "ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffFE ffffffff 00000000 00000000 ffffffFC",
		    // curve coefficient b
		    "B3312FA7 E23EE7E4 988E056B E3F82D19 181D9C6E FE814112 0314088F 5013875A C656398D 8A2ED19D 2A85C8ED D3EC2AEF",
		    // prime p
		    "ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe ffffffff 00000000 00000000 ffffffff",
		    // basepoint G
		    "04 AA87CA22 BE8B0537 8EB1C71E F320AD74 6E1D3B62 8BA79B98 59F741E0 82542A38 5502F25D BF55296C 3A545E38 72760AB7 3617DE4A 96262C6F 5D9E98BF 9292DC29 F8F41DBD 289A147C E9DA3113 B5F0B8C0 0A60B1CE 1D7E819D 7A431D7C 90EA0E5F",
		    // order of basepoint G
		    "ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff C7634D81 F4372DDF 581A0DB2 48B0A77A ECEC196A CCC52973",
		    // cofactor k
		    "01");
	}
    }

    public static final class Secp521r1 extends CurveParamsGFP {

	/**
	 * The OID of secp521r1.
	 */
	public static final String OID = "1.3.132.0.35";

	public Secp521r1() {
	    super(
		    OID,
		    // curve coefficient a
		    "01ff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffFC",
		    // curve coefficient b
		    "0051 953EB961 8E1C9A1F 929A21A0 B68540EE A2DA725B 99B315F3 B8B48991 8EF109E1 56193951 EC7E937B 1652C0BD 3BB1BF07 3573DF88 3D2C34F1 EF451FD4 6B503F00",
		    // prime p
		    "01ff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff",
		    // basepoint G
		    "04 00C6858E 06B70404 E9CD9E3E CB662395 B4429C64 8139053F B521F828 AF606B4D 3DBAA14B 5E77EFE7 5928FE1D C127A2ff A8DE3348 B3C1856A 429BF97E 7E31C2E5 BD660118 39296A78 9A3BC004 5C8A5FB4 2C7D1BD9 98F54449 579B4468 17AFBD17 273E662C 97EE7299 5EF42640 C550B901 3FAD0761 353C7086 A272C240 88BE9476 9FD16650",
		    // order of basepoint G
		    "01ff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffFA 51868783 BF2F966B 7FCC0148 F709A5D0 3BB5C9B8 899C47AE BB6FB71E 91386409",
		    // cofactor k
		    "01");
	}
    }

    /* ECC brainpool */

    public static final class BrainpoolP160r1 extends CurveParamsGFP {

	/**
	 * The OID of brainpoolP160r1.
	 */
	public static final String OID = "1.3.36.3.3.2.8.1.1.1";

	public BrainpoolP160r1() {
	    super(
		    OID,
		    // curve coefficient a
		    "340E7BE2A280EB74E2BE61BADA745D97E8F7C300",
		    // curve coefficient b
		    "1E589A8595423412134FAA2DBDEC95C8D8675E58",
		    // prime p
		    "E95E4A5F737059DC60DFC7AD95B3D8139515620F",
		    // basepoint G
		    "04 BED5AF16EA3F6A4F62938C4631EB5AF7BDBCDBC3 1667CB477A1A8EC338F94741669C976316DA6321",
		    // order of basepoint G
		    "E95E4A5F737059DC60DF5991D45029409E60FC09", "01");
	}
    }

    public static final class BrainpoolP192r1 extends CurveParamsGFP {

	/**
	 * The OID of brainpoolP192r1.
	 */
	public static final String OID = "1.3.36.3.3.2.8.1.1.3";

	public BrainpoolP192r1() {
	    super(
		    OID,
		    // curve coefficient a
		    "6A91174076B1E0E19C39C031FE8685C1CAE040E5C69A28EF",
		    // curve coefficient b
		    "469A28EF7C28CCA3DC721D044F4496BCCA7EF4146FBF25C9",
		    // prime p
		    "C302F41D932A36CDA7A3463093D18DB78FCE476DE1A86297",
		    // basepoint G
		    "04 C0A0647EAAB6A48753B033C56CB0F0900A2F5C4853375FD6 14B690866ABD5BB88B5F4828C1490002E6773FA2FA299B8F",
		    // order of basepoint G
		    "C302F41D932A36CDA7A3462F9E9E916B5BE8F1029AC4ACC1",
		    // cofactor k
		    "1");
	}
    }

    public static final class BrainpoolP224r1 extends CurveParamsGFP {

	/**
	 * The OID of brainpoolP224r1.
	 */
	public static final String OID = "1.3.36.3.3.2.8.1.1.5";

	public BrainpoolP224r1() {
	    super(
		    OID,
		    // curve coefficient a
		    "68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43",
		    // curve coefficient b
		    "2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B",
		    // prime p
		    "D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF",
		    // basepoint G
		    "04 0D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D 58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD",
		    // order of basepoint G
		    "D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F",
		    // cofactor k
		    "1");
	}
    }

    public static final class BrainpoolP256r1 extends CurveParamsGFP {

	/**
	 * The OID of brainpoolP256r1.
	 */
	public static final String OID = "1.3.36.3.3.2.8.1.1.7";

	public BrainpoolP256r1() {
	    super(
		    OID,
		    // curve coefficient a
		    "7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9",
		    // curve coefficient b
		    "26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6",
		    // prime p
		    "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377",
		    // basepoint G
		    "04 8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262 547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997",
		    // order of basepoint G
		    "A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7",
		    // cofactor k
		    "1");
	}
    }

    public static final class BrainpoolP320r1 extends CurveParamsGFP {

	/**
	 * The OID of brainpoolP320r1.
	 */
	public static final String OID = "1.3.36.3.3.2.8.1.1.9";

	public BrainpoolP320r1() {
	    super(
		    OID,
		    // curve coefficient a
		    "3EE30B568FBAB0F883CCEBD46D3F3BB8A2A73513F5EB79DA66190EB085FFA9F492F375A97D860EB4",
		    // curve coefficient b
		    "520883949DFDBC42D3AD198640688A6FE13F41349554B49ACC31DCCD884539816F5EB4AC8FB1F1A6",
		    // prime p
		    "D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27",
		    // basepoint G
		    "04 43BD7E9AFB53D8B85289BCC48EE5BFE6F20137D10A087EB6E7871E2A10A599C710AF8D0D39E20611 14FDD05545EC1CC8AB4093247F77275E0743FFED117182EAA9C77877AAAC6AC7D35245D1692E8EE1",
		    // order of basepoint G
		    "D35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311",
		    // cofactor k
		    "1");
	}
    }

    public static final class BrainpoolP384r1 extends CurveParamsGFP {

	/**
	 * The OID of brainpoolP384r1.
	 */
	public static final String OID = "1.3.36.3.3.2.8.1.1.11";

	public BrainpoolP384r1() {
	    super(
		    OID,
		    // curve coefficient a
		    "7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826",
		    // curve coefficient b
		    "4A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11",
		    // prime p
		    "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53",
		    // basepoint G
		    "04 1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E 8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315",
		    // order of basepoint G
		    "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565",
		    // cofactor k
		    "1");
	}
    }

    public static final class BrainpoolP512r1 extends CurveParamsGFP {

	/**
	 * The OID of brainpoolP512r1.
	 */
	public static final String OID = "1.3.36.3.3.2.8.1.1.13";

	public BrainpoolP512r1() {
	    super(
		    OID,
		    // curve coefficient a
		    "7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA",
		    // curve coefficient b
		    "3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723",
		    // prime p
		    "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3",
		    // basepoint G
		    "04 81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822 7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892",
		    // order of basepoint G
		    "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069",
		    // cofactor k
		    "1");
	}
    }

    /* CDC */

    public static final class PrimeCurve1 extends CurveParamsGFP {

	/**
	 * The OID of primeCurve1.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.2.9.0.1";

	public PrimeCurve1() {
	    super(
		    OID,
		    // curve coefficient a
		    "1DCB49C5 8770F58C 69C79F97 F60DD78F 7118E821",
		    // curve coefficient b
		    "1D78807E 19BD084D D030EACC A927D930 0C6D58D6",
		    // prime p
		    "9115fd05 8b000000 ea770ce5 f693658a ad431707",
		    // basepoint G
		    "04 2B34420F 73F08BD5 5A8B0E73 3DAB7880 A0CA2673 21B657AB 425FCB27 C55249A1 D2717AC3 2427510F",
		    // order of basepoint G (200 Bit)
		    "9115FD05 8B000000 EA7838B4 A173F0DD 06F4B979",
		    // cofactor k
		    "01");
	}
    }

    public static final class PrimeCurve2 extends CurveParamsGFP {

	/**
	 * The OID of primeCurve2.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.2.9.0.2";

	public PrimeCurve2() {
	    super(
		    OID,
		    // curve coefficient a
		    "0183 c32b004a db9e04a5 b247bbb9 60ee557c 4ecefb85",
		    // curve coefficient b
		    "0364 60462b23 3d140326 b4055a58 bf1e3d78 f856cd7c",
		    // prime p
		    "0392 cd3e406a 00000014 5bc04bcb bdbf06b9 25b338b5",
		    // basepoint G
		    "04 00000273 7b073c38 211f9625 257a02b9 3aec7c9e e6eb8f28 00000254 dcf9a43c 0fd8ee70 d9a99a4e 7c3e8979 c31562de",
		    // order of basepoint G (210 Bit)
		    "0392 cd3e406a 00000014 5bee0d56 ecebde5d 7129334f",
		    // cofactor k
		    "01");
	}
    }

    public static final class PrimeCurve3 extends CurveParamsGFP {

	/**
	 * The OID of primeCurve3.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.2.9.0.3";

	public PrimeCurve3() {
	    super(
		    OID,
		    // curve coefficient a
		    "a69e83ab7c98fd714c7a7b7a93af1954dd132e862ec02",
		    // curve coefficient b
		    "5dbbcad7b37c242f502b0c2eb82998a30f825ed09ac85",
		    // prime p
		    "e1a16196e6000000000bc7799af40e45f20c282a73f23",
		    // basepoint G
		    "04 0007a00d eb0f6992 bab23365 2ddb5c6f 331d7d27 0f9709ec 0005894d 1f3f9957 3cc01c7f 9ab750bd e3a6a11e 4b2c8e9e",
		    // order of basepoint G (220 Bit)
		    "e1a16196e6000000000bc7f1618d867b15bb86474418f",
		    // cofactor k
		    "01");
	}
    }

    public static final class PrimeCurve4 extends CurveParamsGFP {

	/**
	 * The OID of primeCurve4.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.2.9.0.4";

	public PrimeCurve4() {
	    super(
		    OID,
		    // curve coefficient a
		    "11111e2ca8d70000c01a940cf21e2b0bec51218f05a1ecc3",
		    // curve coefficient b
		    "281abd44258f5555d5675fc47fbc5b10b043ff05ff748bc4",
		    // prime p
		    "2b16fdb98f80000000007b99cd7c5d8d1c14dcf9f98ce4e3",
		    // basepoint G
		    "04 2a8d51b9 f230d0ba 7e4cf806 342dd921 9d463999 5467f403 0be85468 ba272003 7a6cd96a aaf132d6 f4bec7c6 68ee5b39",
		    // order of basepoint G (224 Bit)
		    "2b16fdb98f80000000007b99e8c92d2e2d913c958101d14d",
		    // cofactor k
		    "01");
	}
    }

    public static final class PrimeCurve5 extends CurveParamsGFP {

	/**
	 * The OID of primeCurve5.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.2.9.0.5";

	public PrimeCurve5() {
	    super(
		    OID,
		    // curve coefficient a
		    "831bcff1c93ad4b2f433764c85601b92d40e3f2f670eba66cc",
		    // curve coefficient b
		    "a0bd08614f984050a20e18b98c562a725cebc993a21414eda9",
		    // prime p
		    "db7a31ea4600000000000708008969b73d2dcfa41d659bbabb",
		    // basepoint G
		    "04 1de9 9de08a53 4f974e13 d118cc91 2fd147bc cf358ae7 e13e307e 1d3f5b97 6816a1b7 f7e58619 b3912663 ae6dc5ea 98f14eb4",
		    // order of basepoint G (230 Bit)
		    "db7a31ea46000000000007081d1966e39c65396b89596ef345",
		    // cofactor k
		    "01");
	}
    }

    public static final class PrimeCurve6 extends CurveParamsGFP {

	/**
	 * The OID of primeCurve6.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.2.9.0.6";

	public PrimeCurve6() {
	    super(
		    OID,
		    // curve coefficient a
		    "1703654f4b34338c2b63dcfa43193ca95c7bd1d32e12bc858809b",
		    // curve coefficient b
		    "1d9abbeb87ac65f3227c32a95fdfe7ecd331ab000675e592afaa0",
		    // prime p
		    "2f074f112ec000000000000d82dccb24bbbd1eca0054ea85e650f",
		    // basepoint G
		    "04 00018363 23f55807 47d67753 145db89b e5201eb7 35fd7854 228b8683 00028ae1 4e4170f8 e4d9f357 9123187b 8817dd98 4c0ee154 ed167350",
		    // order of basepoint G (239 Bit)
		    "2f074f112ec000000000000d830f5c018aec38cb492dcd1fe467b",
		    // cofactor k
		    "01");
	}
    }

    public static final class PrimeCurve7 extends CurveParamsGFP {

	/**
	 * The OID of primeCurve7.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.2.9.0.7";

	public PrimeCurve7() {
	    super(
		    OID,
		    // curve coefficient a
		    "1adaab88b85337d93c4083a50455ac62c6656112bd4255d17929c84",
		    // curve coefficient b
		    "c8dbedf53b7f40daec446884f66f49c16b9aafde8750f417529aa8d",
		    // prime p
		    "ee598703e9000000000000045e7dee63b0c647dfce8e787ec106591",
		    // basepoint G
		    "04 01fd1b7c c5b2d2c4 08376fe3 8266359d f0ba6381 45b56fe7 beec5ba9 0277d80a 1927c9a5 5a1df108 6a09e37b 0a1d02c1 b89550a8 310f4538",
		    // order of basepoint G (239 Bit)
		    "ee598703e9000000000000045e8081bebc1ab4f10af8679da2d63b5",
		    // cofactor k
		    "01");
	}
    }

    public static final class PrimeCurve8 extends CurveParamsGFP {

	/**
	 * The OID of primeCurve8.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.2.9.0.8";

	public PrimeCurve8() {
	    super(
		    OID,
		    // curve coefficient a
		    "ffffffff ffffffff ffffffff fffffffe ffffffff ffffffff fffffffe",
		    // curve coefficient b
		    "B4050A85 0C04B3AB F5413256 5044B0B7 D7BFD8BA 270B3943 2355ffB4",
		    // prime p
		    "ffffffff ffffffff ffffffff ffffffff 00000000 00000000 00000001",
		    // basepoint G
		    "04 B70E0CBD 6BB4BF7F 321390B9 4A03C1D3 56C21122 343280D6 115C1D21 BD376388 B5F723FB 4C22DFE6 CD4375A0 5A074764 44D58199 85007E34",
		    // order of basepoint G (239 Bit)
		    "ffffffff ffffffff ffffffff ffff16A2 E0B8F03E 13DD2945 5C5C2A3D",
		    // cofactor k
		    "01");
	}
    }

    public static final class PrimeCurve9 extends CurveParamsGFP {

	/**
	 * The OID of primeCurve9.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.2.9.0.9";

	public PrimeCurve9() {
	    super(
		    OID,
		    // curve coefficient a
		    "2660c8176110678d81d34b41db0060f3366e583f6185af6d34570021c1",
		    // curve coefficient b
		    "c4a1d2b80bf3e925d5482c71edff11712ac0101a1d82ef935c1298ae7",
		    // prime p
		    "2c082db5a220000000000000022753b218a0dbcb93ca32a5f2e1523271",
		    // basepoint G
		    "04 00000012 00ce14c8 c075f7c9 19ef0cd7 7ba4992d 15deb40f 99e6c020 90a0293e 0000001c 3573745f cd0716b8 10d295de b7dc5a81 ad4a45d2 44ec0024 42226e40",
		    // order of basepoint G (240 Bit)
		    "2c082db5a2200000000000000227602942c8b44be7f5c3ff2a4e8a9a87",
		    // cofactor k
		    "01");
	}
    }

    public static final class PrimeCurve10 extends CurveParamsGFP {

	/**
	 * The OID of primeCurve10.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.2.9.0.10";

	public PrimeCurve10() {
	    super(
		    OID,
		    // curve coefficient a
		    "5b37329be5137cda74229c44b5a0f65b823dd8f6e69cf74e7331e70120b7",
		    // curve coefficient b
		    "62528ed081cc36f8f27759590be7f2c36a72a340e1c0cce61270d7f1a057",
		    // prime p
		    "dc2508a6ff8000000000000000861fb40add5a8a6792bf511c546ffe6205",
		    // basepoint G
		    "04 a8da80da25a5ab5c8f3fda77bbe0b7049b0a804b8c6d394a9582b541bfc3 af3f72df1828f26a3d335c572ff67d1bc6f1289f5ee93ef98f529e46aaae",
		    // order of basepoint G (250 Bit)
		    "dc2508a6ff80000000000000008621512f35fc6fd101d5b8487ed3e5897f",
		    // cofactor k
		    "01");
	}
    }

    public static final class PrimeCurve11 extends CurveParamsGFP {

	/**
	 * The OID of primeCurve11.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.2.9.0.11";

	public PrimeCurve11() {
	    super(
		    OID,
		    // curve coefficient a
		    "19b70887a8b73de2e7bf533e7d6ef32b75a8e7473e18a8eea262515a3165b42",
		    // curve coefficient b
		    "218e054fe79a2941efd4e229a8f573b4b02ac410113e173573735f0cc9e4515",
		    // prime p
		    "313bfee06560000000000000000274c7252e7da1b788f3c315957a71fae18bb",
		    // basepoint G
		    "04 02b1ccd3 99921913 bcc7182c 6440c492 007bb9aa a0fdb385 e3ab2f98 eafc50e5 00818782 bbe460b0 d5b35136 29f7bdc9 7a8acc17 658589ab 9106b826 23eb4c78",
		    // order of basepoint G (256 Bit)
		    "313bfee06560000000000000000274c750d4f83bbe1f0c9ffc4907e5bd6ee09",
		    // cofactor k
		    "01");
	}
    }

    public static final class PrimeCurve12 extends CurveParamsGFP {

	/**
	 * The OID of primeCurve12.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.2.9.0.12";

	public PrimeCurve12() {
	    super(
		    OID,
		    // curve coefficient a
		    "81dd193a6ca87e725e0dfaccc7a69375c297042ceb87fb7137bee8c5a2e0580e7",
		    // curve coefficient b
		    "829da57e48b6a3852917f352b1960549245c8b1f0f97c54858f1e40db6262aa50",
		    // prime p
		    "8673224524800000000000000000373f4522e7b595a33243ec69326ccc3ba87f9",
		    // basepoint G
		    "04 0008 611c4182 eae61231 6cac12cc cef65cea acc4a8b8 b91928fe 86521e58 3793e7b4 0005 1ac8dac7 c3cb20bd 4c491674 68841a96 8158f57e 71b9ae74 70e5e8d9 b7493721",
		    // order of basepoint G (260 Bit)
		    "8673224524800000000000000000373f8280ed95437673ddcfcabff8b8c08da7f",
		    // cofactor k
		    "01");
	}
    }

    public static final class PrimeCurve13 extends CurveParamsGFP {

	/**
	 * The OID of primeCurve13.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.2.9.0.13";

	public PrimeCurve13() {
	    super(
		    OID,
		    // curve coefficient a
		    "1ac66642e4cab5c37b5084e2e36248488cabc5b42d57a3b10e9aa1f0f0201912140",
		    // curve coefficient b
		    "1bf8b6369748723d7a78b0341ecec343121df8f4b13d78a4b617769e383fcebbd4f6",
		    // prime p
		    "2848aaedb4a00000000000000000006012623913c706babc003987ce455db4889e31",
		    // basepoint G
		    "04 2450ac5a 508c693e 9d2efe3e fbfba2b5 4d1a1cc9 71d330a6 6dc7c598 05db73cd f26b15c0 149790d3 688d4eb6 7f2ebe51 8a87e266 bbe6c400 167ca4fb dc976122 d6bcd80f",
		    // order of basepoint G (270 Bit)
		    "2848aaedb4a00000000000000000006012f587e9863f4a5d2d770c3dca2bbf097695",
		    // cofactor k
		    "01");
	}
    }

    public static final class PrimeCurve14 extends CurveParamsGFP {

	/**
	 * The OID of primeCurve14.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.2.9.0.14";

	public PrimeCurve14() {
	    super(
		    OID,
		    // curve coefficient a
		    "209fe271311b2de7fd362334cc58b1665a4b3d65c8b8339f62b472f0c3306c79babc4b",
		    // curve coefficient b
		    "515aab12f8921e9aa8cec22332e5cb9bcc8e7c9a3bbe922adec8d419648c6b664b5fff",
		    // prime p
		    "b2d03c56878000000000000000000006b114fb0321cb4f41d6f1966aa744693f6ca767",
		    // basepoint G
		    "04 52cea7d705a050b6d123cdd1c0ca59359e46fb27c9c112bc2953d63553fa50d852d89e a9c8d272c7cd91caf2f416a18388ab5d75bbac9de55aee7d5eb810f1961504207240fa",
		    // order of basepoint G (280 Bit)
		    "b2d03c56878000000000000000000006b12e6c342e3b5c5bcacd5b953f1409784d260f",
		    // cofactor k
		    "01");
	}
    }

    public static final class PrimeCurve15 extends CurveParamsGFP {

	/**
	 * The OID of primeCurve15.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.2.9.0.15";

	public PrimeCurve15() {
	    super(
		    OID,
		    // curve coefficient a
		    "2d3eb0d2f1acadcb6e5a45e634617af9e30611992f9719574a7266da27c2c0a743f0356b7",
		    // curve coefficient b
		    "90a6521245dfed9b606ba4bc1121142c8c585405daf5ab778a6dc0eeda96d7b7298a0df6",
		    // prime p
		    "3463b86e96c00000000000000000000025f44d4824ffad5c1fb9526a2de06ad7343d3c2e3",
		    // basepoint G
		    "04 0000 2235e999 d0a7d534 c67c1df0 5e2a6ac3 55e373ac 1485b844 3cc24a95 ef89edf2 6970bb33 0001 e3dab4cb bae52510 a95afa74 bca8e45d 35550312 b406322c 6c8fd301 ddc5a51f 91159759",
		    // order of basepoint G (290 Bit)
		    "3463b86e96c00000000000000000000025f4656a5213f91a62eb219ca39ffe5e7c0994b01",
		    // cofactor k
		    "01");
	}
    }

    public static final class PrimeCurve16 extends CurveParamsGFP {

	/**
	 * The OID of primeCurve16.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.2.9.0.16";

	public PrimeCurve16() {
	    super(
		    OID,
		    // curve coefficient a
		    "6bbdc4725e87db0d57c8cc7cf653fc836db429d0b56af2e001a757979c2b5441f8a9ff689c5",
		    // curve coefficient b
		    "47d3d84c3f053cb38fdb32fdf98d53024922c68b239ca1eaabc4e50fbd72382bfb1bff9b12e",
		    // prime p
		    "94a2e34574800000000000000000000001f56a7e0ee33cbb0d30f0aae667599eef0f1516e03",
		    // basepoint G
		    "04 01ae 9bb0c018 51d3e93c a9bb0f57 e5adff46 40ab1dbb 5027ee95 c8064ce7 2b31cfc5 eb0a7f9a 009e 95a0e74c 70980d37 fa767509 3b1a6005 93b63081 2a53793d 564a422a 09785937 5aba6a86",
		    // order of basepoint G (300 Bit)
		    "94a2e34574800000000000000000000001f56db5baa3aaab36016d66a8928dd8f8a938e89ed",
		    // cofactor k
		    "01");
	}
    }

    public static final class PrimeCurve17 extends CurveParamsGFP {

	/**
	 * The OID of primeCurve17.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.2.9.0.17";

	public PrimeCurve17() {
	    super(
		    OID,
		    // curve coefficient a
		    "16ffdeae533376d7b478636b8cebfee8ce08425656926eee1b68a9e8ca5004287ccf3b9c644489",
		    // curve coefficient b
		    "25b952ce9cd3ad68f09b53e74e6a7a36adb186acce53680715617c0dae532a6ee0ff666620a37f",
		    // prime p
		    "2e760ccec06000000000000000000000000438f3857327072be7edb2b4ed4a99f7308a573dc26d",
		    // basepoint G
		    "04 00233ffd 63ba773e 200380b3 a5f433c6 f7856282 d1f2e13d 15e48715 b55bb563 178cc735 444d50f6 00029da9 8dd8f076 4775b2b9 9affbbae d6efb51a 51b3aaf8 180844c5 75137087 f4809d74 4ca8db91",
		    // order of basepoint G (310 Bit)
		    "2e760ccec06000000000000000000000000438fd414dd433ddda0045e71329ba523bba1f0eb34d",
		    // cofactor k
		    "01");
	}
    }

    public static final class PrimeCurve18 extends CurveParamsGFP {

	/**
	 * The OID of primeCurve18.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.2.9.0.18";

	public PrimeCurve18() {
	    super(
		    OID,
		    // curve coefficient a
		    "79cb7d16b8f76109a6ad2a3d51f39046312d78e2a6a2f9783b3f53309e9b6be1429ca6b8e952624e",
		    // curve coefficient b
		    "6d75dde70e4ca8b395f686e64dc4d93a32352cb786b0f3b6f25ba9419bb4d38943e3a9b99582ed3c",
		    // prime p
		    "ced4dbaf9580000000000000000000000000e8d5d582902f0b1ce0d35778b9b8552dbf5d26057a93",
		    // basepoint G
		    "04 1d4f1a1fc727f8d5cded3ceca3388d2483496b929ffbfa18b0c3b7e9e08c492b7220b3e3a39fb849 582560f3a96324ac9d5f79ec9678198ac5b9b3b770a12f7fc02ffb2634e2ea92ef126e4cc04f439f",
		    // order of basepoint G (320 Bit)
		    "ced4dbaf9580000000000000000000000000e8d72aa49d6fd22838b3010e204ec5610740cf657439",
		    // cofactor k
		    "01");
	}
    }

    public static final class PrimeCurve19 extends CurveParamsGFP {

	/**
	 * The OID of primeCurve19.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.2.9.0.19";

	public PrimeCurve19() {
	    super(
		    OID,
		    // curve coefficient a
		    "13f7bb00b3b12782ef9e88f0e70b7b7f1c06a2d1a8790e3b4ced902fb9c47f25bed917519ae84c5cbce",
		    // curve coefficient b
		    "3219b247b8f68dc72ac8c9bcbecbd437d9b80f0a6199c39476e71cfd8af4d977f292b96fd093c4d0f41",
		    // prime p
		    "3875a127298000000000000000000000000000b65e7577dcd9cc0bded1bfbbf515279b007020b360c03",
		    // basepoint G
		    "04 01f0 b5dfea61 ee50f27b ce740876 5d63fdf8 a7d61927 10952bc4 291ab809 a0f7b4aa 153544d0 b3951ee1 0045 c738c263 ebff3e87 96da80b7 f8a60e3d 5b557b8b f3d8ed7a b12d77c0 2e6e0446 c1543a3d 41f3061e",
		    // order of basepoint G (330 Bit)
		    "3875a127298000000000000000000000000000b6619eade87aa06a96a2cc93347d8e25c2f23d6cf096d",
		    // cofactor k
		    "01");
	}
    }

    public static final class PrimeCurve20 extends CurveParamsGFP {

	/**
	 * The OID of primeCurve20.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.2.9.0.20";

	public PrimeCurve20() {
	    super(
		    OID,
		    // curve coefficient a
		    "7d4ab4a694577054ad45439844c0d31bceacc015a53e0f2ab5b9031327405df38d8b96de921de9f779b19",
		    // curve coefficient b
		    "9c1baca49e3a4ae31e2e2d102dd5e21289c8801fdd52410c1ad803948ae26615ea219ca1f66aba17c1bcf",
		    // prime p
		    "d9bd9ca0b20000000000000000000000000000344d7aa4cee51604975226765aa34da828bf045a5851d3b",
		    // basepoint G
		    "04 0004c44b 493f639d 4d1cae36 75c38cc0 bce48477 a32929e2 0675fc48 965ba815 5961531b 87b0f5fb aeec6e4a 000881b7 f3fb8502 1341db43 eae09dd9 d4de1f73 58de52f3 17c9fa42 03f817fb 66dd0a34 fe470480 74ea8fe4",
		    // order of basepoint G (340 Bit)
		    "d9bd9ca0b20000000000000000000000000000344daceee6f1673d802df3ffde2d0f1e8f03522290e2de5",
		    // cofactor k
		    "01");
	}
    }

    public static final class PrimeCurve21 extends CurveParamsGFP {

	/**
	 * The OID of primeCurve21.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.2.9.0.21";

	public PrimeCurve21() {
	    super(
		    OID,
		    // curve coefficient a
		    "ba5dbd911ac5484d7eb2e8134a445ea1d82d4349e076d39726045b10513ed5144d8a14aba9202d0a4c908c8",
		    // curve coefficient b
		    "5288994b812a7df9f2607128e335e63ebc99a7a2a9eb0cac8f8f2b844c8d287034591795c84e48e1a0e1ecf",
		    // prime p
		    "21d4fdcd6dc0000000000000000000000000000031a34d3326e97e38aef0d0a27cfc9df1c023d2648bec43a7",
		    // basepoint G
		    "04 1f9d669e 3808e794 d38ea150 038f34f9 74bc1093 52fd6a20 b9af6272 8e6afe75 6fa859d8 839a655d e7076917 13c41e35 0eb4f20e 10693f3c 649715af 76c2d24c 909f48da a0d6bc8f 10c80166 d9416c54 a27d6ef1 5abd7900",
		    // order of basepoint G (350 Bit)
		    "21d4fdcd6dc0000000000000000000000000000031a3dceccff88765b6aa46e4b1ccf634fd5738563ef25b55",
		    // cofactor k
		    "01");
	}
    }

    public static final class PrimeCurve22 extends CurveParamsGFP {

	/**
	 * The OID of primeCurve22.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.2.9.0.22";

	public PrimeCurve22() {
	    super(
		    OID,
		    // curve coefficient a
		    "5fafffcff4592325d29ef117898e5939385747c6cc1cfa1f565caa6b522b73e308b4d81252749bf769448250bd",
		    // curve coefficient b
		    "5de847e38c14b312bc0442b3ad766cb6de8fe2dcc4cfbf4011e390a5ae840781d333b058daac8a672ce26f6195",
		    // prime p
		    "8b2c3d3eed80000000000000000000000000000011a5be697bc7ac0bed5e0be702d1e75f004986292c3cbfb15b",
		    // basepoint G
		    "04 003e 92ade9a2 1c76eab9 f472d964 3f534bef dcc77377 ee49f145 fe486250 4605f6be daf125ef 9d2f9b43 008f958f 002a 1e1cc076 72b66584 054f6c86 23eaff39 d5311570 78b962e8 da2f21de a9cc6d79 d2d699aa d1ee8091 849fc4fb",
		    // order of basepoint G (360 Bit)
		    "8b2c3d3eed80000000000000000000000000000011a5c1bd861979ec761e6bc6371effe3127450ec8818f25a71",
		    // cofactor k
		    "01");
	}
    }

    public static final class PrimeCurve23 extends CurveParamsGFP {

	/**
	 * The OID of primeCurve23.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.2.9.0.23";

	public PrimeCurve23() {
	    super(
		    OID,
		    // curve coefficient a
		    "142423bf5afa93a1405b9ab6e55c6015bbff4e2035bb541cef5801646c984af1f6613839dcba9f3ef72136801a28a",
		    // curve coefficient b
		    "2e6b15419933e4e87742f27fded9b27ad34876e1a085858103b39a07d8b4808bbcd6de8ece938d8cacac40b2c9208",
		    // prime p
		    "311fa5efb580000000000000000000000000000000126dc176924ce0da28dc7a1dd080befb7ce86d03d015e1b1e8f",
		    // basepoint G
		    "04 151f90cc749ee455cc67e09a3289ea34c554d4dbffcccbe95f5699f5f2b2375e2af6a3647ff74b5a758defb1c348 f2b42f4c439264ca1265acf031c5feb775292491f68bc3ebf4de7d51f2a2887eee7555f3e2efc7519d8a7dcfdf01",
		    // order of basepoint G (370 Bit)
		    "311fa5efb580000000000000000000000000000000126dca86aafb4948bf113acbf5868e662ce192d518adb1552b7",
		    // cofactor k
		    "01");
	}
    }

    public static final class PrimeCurve24 extends CurveParamsGFP {

	/**
	 * The OID of primeCurve24.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.2.9.0.24";

	public PrimeCurve24() {
	    super(
		    OID,
		    // curve coefficient a
		    "12be2e237a36fbf14e1295394574a5823426853ab7234eb16a791afcacefe2caf48a9f4905cec208161f7d4f5a5ad6e",
		    // curve coefficient b
		    "c7ec96cfc24a7f6340c637b83a319017819ae2724c2347646fb67531df541dca30714db5934815ab96a538a3c3c8f4",
		    // prime p
		    "8703f514c60000000000000000000000000000000003ae5e57f36cd85df9ed0c1cae446d67bed29daf879bbaebd1dcf",
		    // basepoint G
		    "04 027d518a a0a19cfd 6db84fea d2d4d568 770d5bfa ab39ee63 efbae7c7 f1996782 4361c79a 094ce6bc 5cf6e2c1 3b11f715 07e95e22 54654786 fdbd2ec5 4a5723eb 8b05435a ed146ed7 0848f3ab d9c7a216 13a3fd6a 196512fd 15a42567 c7b46550",
		    // order of basepoint G (380 Bit)
		    "8703f514c60000000000000000000000000000000003ae614f73789e91fb8aa0a76372a4b806cf890749222dd04562b",
		    // cofactor k
		    "01");
	}
    }

    public static final class PrimeCurve25 extends CurveParamsGFP {

	/**
	 * The OID of primeCurve25 (this is also the NIST curve P-384).
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.2.9.0.25";

	public PrimeCurve25() {
	    super(
		    OID,
		    // curve coefficient a
		    "ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffFE ffffffff 00000000 00000000 ffffffFC",
		    // curve coefficient b
		    "B3312FA7 E23EE7E4 988E056B E3F82D19 181D9C6E FE814112 0314088F 5013875A C656398D 8A2ED19D 2A85C8ED D3EC2AEF",
		    // prime p
		    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
		    // basepoint G
		    "04 AA87CA22 BE8B0537 8EB1C71E F320AD74 6E1D3B62 8BA79B98 59F741E0 82542A38 5502F25D BF55296C 3A545E38 72760AB7 3617DE4A 96262C6F 5D9E98BF 9292DC29 F8F41DBD 289A147C E9DA3113 B5F0B8C0 0A60B1CE 1D7E819D 7A431D7C 90EA0E5F",
		    // order of basepoint G (384 Bit)
		    "ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff C7634D81 F4372DDF 581A0DB2 48B0A77A ECEC196A CCC52973",
		    // cofactor k
		    "01");
	}
    }

    public static final class PrimeCurve26 extends CurveParamsGFP {

	/**
	 * The OID of primeCurve26.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.2.9.0.26";

	public PrimeCurve26() {
	    super(
		    OID,
		    // curve coefficient a
		    "8e5d2e91dc4971a706b8cd28e6e1e6161128bed614462ba363637546e9852ea063f894e6d13165698ad52dd4241044b89",
		    // curve coefficient b
		    "bac59073d3ebfc8479a27a67fccc79693744f4cb686394fbb755dadaa466eb50f6b82e6851fa8e47a3728e657f702d0a6",
		    // prime p
		    "22735b746380000000000000000000000000000000000a0d141275163a6f62f90933ff317c958cb9100f1c45adf16263e5",
		    // basepoint G
		    "04 0010 a33ad7b9 8f9610b6 1081a047 bac7e5d7 2fe08a3b 0f62bcec df329136 a3fd4174 c1c12e0d 9d174b87 8fa43cfc a95aa0bd 001a 359492ef eac118dc fb6ca3d2 332ccbe3 09611b50 82e5ecc5 ee2583f8 a99f2a9f 3a468f1d 96cdcbe2 393a808d f19a4ba5",
		    // order of basepoint G (390 Bit)
		    "22735b746380000000000000000000000000000000000a0d1635b4746ba6c5fbc4228ae0c337481db4dd15e4d479d8b71f",
		    // cofactor k
		    "01");
	}
    }

    public static final class PrimeCurve27 extends CurveParamsGFP {

	/**
	 * The OID of primeCurve27.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.2.9.0.27";

	public PrimeCurve27() {
	    super(
		    OID,
		    // curve coefficient a
		    "872bf37c637ba3a52f66babaca2b2757b2e760aaba04da95158bda68cda285793adeb73112ce7f06304709fb30fced2ea4e8",
		    // curve coefficient b
		    "4b70d12707b7f6094a4ed97e05b32ad3879a04f9f58182be59dd12d5f1d51a92553ad0803ef61644880ca71c997db5ea418f",
		    // prime p
		    "916af0af9700000000000000000000000000000000000094b482291a115eee4cf289a602461a64e305062316854ce611d465",
		    // basepoint G
		    "04 58ac293a65988a11077532b34b62c1654a802cca2030456bb9fec1b9c89a1d133740cf1874cbe256ee2d12e967acd68e45ed 6f829061efadab7881611d566db8dbe61db3b80d0a48bd263772ac877f9253c49bc03d2f63c8721c65e9df123338c4eacd50",
		    // order of basepoint G (400 Bit)
		    "916af0af9700000000000000000000000000000000000094b4c943d1aaa84cb74f1992f4abffcc48e7b7d6748bddebbd6c8f",
		    // cofactor k
		    "01");
	}
    }

    public static final class PrimeCurve28 extends CurveParamsGFP {

	/**
	 * The OID of primeCurve28.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.2.9.0.28";

	public PrimeCurve28() {
	    super(
		    OID,
		    // curve coefficient a
		    "3b41ef140ceaa3739fe0cd1831214a6713a3aad97362451c0f851efaee2eefadda47c24304bd94752b193b8f1c9dd5a16dbfad1",
		    // curve coefficient b
		    "125a635390e717a26a95de1020c0dc44b7c271e64cec2e12441d9a18cd7d1a8a5bd32b57c5cdf998daa239d51d0e20889b1510d",
		    // prime p
		    "3f74b42d672000000000000000000000000000000000000152b16fab73e68fbca116027eb8113c1fc64bc99ee21149a90a4027b",
		    // basepoint G
		    "04 01b396e6 43e53d73 b78b4b97 43a92791 0c75c1fe f9b5269f cdd0fa23 767a8867 63a2e1d0 0477c0e5 c8568109 0fcf2f8b 73236e77 03d95386 d7bf600b ae64c966 86dd9080 3da442d8 1b20c2b8 6c59dbc7 abd28c6c 8d30f795 7a2beb06 55eacb27 1bdfb8ea 2c0eaedd",
		    // order of basepoint G (410 Bit)
		    "3f74b42d672000000000000000000000000000000000000152b3b20a1ff71055fd3bd8bbf04f13be5ceb19e69003d4109d602e7",
		    // cofactor k
		    "01");
	}
    }

    public static final class PrimeCurve29 extends CurveParamsGFP {

	/**
	 * The OID of primeCurve29.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.2.9.0.29";

	public PrimeCurve29() {
	    super(
		    OID,
		    // curve coefficient a
		    "73295afa69e38110260d725104749acadec668b5bab83c9d9c78ee204a1542ee2e3954393820f74fbdcdecb8c0b9de7658537dd65",
		    // curve coefficient b
		    "756762904bfee66d084915def7e31dd9e982cf8a3183805e395c7e994e57c35c6cf2706e132d3d71509a3e79b19d4313b1b1c5c90",
		    // prime p
		    "f02b900845000000000000000000000000000000000000003c76c81182190cec1f2e3d48be46e738838b908f291dab5069c623bd5",
		    // basepoint G
		    "04 000d 937e26bb 6d7a9f86 1a0054a4 c7ebaf14 42df5d08 bbabf6be ea86b171 836c3929 33e0c1c7 52e628e2 7f5de785 c2d2d940 162b7d8d 0000 b5696799 148d67a1 655a257a f6b6485b f4827d76 81aa221c f400e954 b5a56b94 6497487c 1a5151f1 aa234709 b0e774ab c41274e3",
		    // order of basepoint G (420 Bit)
		    "f02b900845000000000000000000000000000000000000003c7696f767282da313260fc5204a6a473f36c2a1d428f1fc368d3b655",
		    // cofactor k
		    "01");
	}
    }

    public static final class PrimeCurve30 extends CurveParamsGFP {

	/**
	 * The OID of primeCurve30.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.2.9.0.30";

	public PrimeCurve30() {
	    super(
		    OID,
		    // curve coefficient a
		    "b23713a507b955c7f208dceabca250c10d73b61c921e5011f593a096b9e41d86defa0a2d105b5b44e5e893bf75b467d94b3bdab1fd0",
		    // curve coefficient b
		    "2130e3a2f1fd0e3daa15b3df1d316e080b3a2796861698ab6aa756aa21b799a30565197c3caac8cc4c7b0b2ab0aa6fb93d0c2f8c99fe",
		    // prime p
		    "26a5e43a1a8000000000000000000000000000000000000000a1c7f5c6f5249c1a28059789fa777e245a078411a4611846de89a7c72d",
		    // basepoint G
		    "04 1c6d 090272a8 acdb77db 0ea8b2d7 6d649fd3 f9feb1e0 49332cb7 cacf41a6 b255d71c c92d1bf9 2158fd0b ca16bf35 d2e0a8f0 44dcc9a9 0017 e3697e5c 0921fbf5 127b3dfc 557646d0 f6ea1eee f1fea323 ad70ff3d 973e41dd 47c03461 7336fc99 64f31815 fae56419 a7367e8e",
		    // order of basepoint G (430 Bit)
		    "26a5e43a1a8000000000000000000000000000000000000000a1c8123cde05d7a482570b8e1bba7985346082a78df7963d08b4aacc73",
		    // cofactor k
		    "01");
	}
    }

    public static final class PrimeCurve31 extends CurveParamsGFP {

	/**
	 * The OID of primeCurve31.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.2.9.0.31";

	public PrimeCurve31() {
	    super(
		    OID,
		    // curve coefficient a
		    "963e5a3b08fe13b37dc849eaa7af2592e05c3e3b86f7178f3acd30cd304e8e8c61b472d7a4e4a04565ca25342c32503c8ef038a24e3fc",
		    // curve coefficient b
		    "5504e81cf1a0bbd9bf728e23576727a3c520523e5c3992d5643f2ba2e0a5c6b73a7740465edc424a4feeb1bb2acb97f453b16eea9681a2",
		    // prime p
		    "95f00ca875800000000000000000000000000000000000000003259ff401983ff690dc06cacd5108f23c5f100b174fc56486bd2995584b",
		    // basepoint G
		    "04 002d64e2 e1f1ec49 5a5672f4 6291ca26 7269717f 1c1d9b8c 212317af 170a180c bd9bc70a 8b349f44 e76529d1 724b0470 f5bdbf62 27c3e48c 0086fa54 3f87b89b c8ed533f f8ce24ff 04cc8a28 f4a34285 625a9873 6c4f9df7 2b7a7731 927ca490 e224107e d202f87f b79e4dff 23ba7db2",
		    // order of basepoint G (440 Bit)
		    "95f00ca87580000000000000000000000000000000000000000325b83753e76699bf4924b3e084bf089a11ddf37fd3a8a2a84ddd423507",
		    // cofactor k
		    "01");
	}
    }

    public static final class PrimeCurve32 extends CurveParamsGFP {

	/**
	 * The OID of primeCurve32.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.2.9.0.32";

	public PrimeCurve32() {
	    super(
		    OID,
		    // curve coefficient a
		    "1f93b31740cd4c71b97220d84739aa7f37242f87187e54293f2783af4f7c8255196fe9e1555b505f9d8c3b2367400c16c9cdf447071f06925",
		    // curve coefficient b
		    "150d220f8088dda1264c15e584d11c54cf6d7504bafee2c62a1a57ca34fdac38bb9ff140e392359513b2d2179a2ab2b9dbdea2da04bf59b6e",
		    // prime p
		    "2a86594ba0e00000000000000000000000000000000000000000219d314fc04a8e282791573d1d8be57f31782f7cebc9a7a7891c8e7bd0f23",
		    // basepoint G
		    "04 0002 2eb8452d f21ba019 9785e3f0 564f8dd0 ef80cc4c 077777b0 b6745272 02bc62fb 0beb78ec 64bbb401 545fbddf ef361d9c 3cd5d7d9 2ada3b77 0001 e8f62d4e f4ad4b1a 074325ea 3dfc420c 9fb15a82 3698f947 838b9d26 c50e75a1 48609ff3 46fbede4 2fd97de2 77ffda82 af968609 038f5fbc",
		    // order of basepoint G (450 Bit)
		    "2a86594ba0e00000000000000000000000000000000000000000219d3f99956122a120f22f5cea8476ba191d01d32370664904669f877dee1",
		    // cofactor k
		    "01");
	}
    }

    public static final class PrimeCurve33 extends CurveParamsGFP {

	/**
	 * The OID of primeCurve33.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.2.9.0.33";

	public PrimeCurve33() {
	    super(
		    OID,
		    // curve coefficient a
		    "a377dede6b523333d36c78e9b0eaa3bf48ce93041f6d4fc34014d08f6833807498deedd4290101c5866e8dfb589485d13357b9e78c2d7fbe9fe",
		    // curve coefficient b
		    "a9acf8c8ba617777e248509bcb4717d4db346202bf9e352cd5633731dd92a51b72a4dc3b3d17c823fcc8fbda4da08f25dea89046087342595a7",
		    // prime p
		    "b6172c9d588000000000000000000000000000000000000000000476c850ee692630b909654554e0e97dd79837b8a1cf354a3d0300fec78ecf9",
		    // basepoint G
		    "04 0815 23d03d4f 12cd0287 9dea4bf6 a4f3a7df 26ed888f 10c5b223 5a1274c3 86a2f218 300dee6e d2178411 64533bcd c903f07a 096f9fbf 4ee95bac 098a 111f296f 5830fe5c 35b3e344 d5df3a22 56985f64 fbe6d0ed cc4c61d1 8bef681d d399df3d 0194c5a4 315e012e 0245ecea 56365baa 9e8be1f7",
		    // order of basepoint G (460 Bit)
		    "b6172c9d588000000000000000000000000000000000000000000476c879048e5d85ea728ed2ea1c1db92c4e4f9652364fdcdba7755fa6c362f",
		    // cofactor k
		    "01");
	}
    }

    public static final class PrimeCurve34 extends CurveParamsGFP {

	/**
	 * The OID of primeCurve34.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.2.9.0.34";

	public PrimeCurve34() {
	    super(
		    OID,
		    // curve coefficient a
		    "1dd935aa6b6631b2e501624afe55a3b56620a9ead728711fd9b92b930bfc15543bdbad1151deed313b1dd06be8410daecd84fbc0bfccb2c619a571",
		    // curve coefficient b
		    "1f6b160091d4dd0cb5e287e7e3594240e40f4615a601f60a974b9b64a4d8a8b90e07618f863a74fbd56c6c1459687b233e9e814eecd3c3a5d96edc",
		    // prime p
		    "3c662bc721200000000000000000000000000000000000000000000aa8f4d9623caccaa54e0a686d6544aa8810b6a9d79f530e814c8aa47e285833",
		    // basepoint G
		    "04 0034586d 9c9debf4 67587ede 6924d564 22e2965b f8bac3ed 3ac3b56c df07995c 70520bfd 826eec69 d788a3f8 148e0c90 959315bc 301417cb 2207d660 001eb23d 5e544d1d b0122602 69e3f943 b21f1c50 300456cb 30821d98 5435dfde 82a287b4 95ab7eae a76dae01 3414db8c cc256416 d9a434a4 b72268a1",
		    // order of basepoint G (470 Bit)
		    "3c662bc721200000000000000000000000000000000000000000000aa8fe4971bb219fdf45c5e4b8dba56e04ff9233975de88d409121616f289b4b",
		    // cofactor k
		    "01");
	}
    }

    public static final class PrimeCurve35 extends CurveParamsGFP {

	/**
	 * The OID of primeCurve35.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.2.9.0.35";

	public PrimeCurve35() {
	    super(
		    OID,
		    // curve coefficient a
		    "4c69eb7495141772c04b6342d808fba74802a969c7980bdc985a09301c46851e5c83d4c8bd6915d2e0eef284a5ccab0390e1d8e6e0398751a2197b49",
		    // curve coefficient b
		    "7e0c35299762ba4c8032422c9005fd1a3001c646851007e865915b75e23e22581d1ae52a1b3f816d227b9bb5897607c92931a259f29a7285820baed1",
		    // prime p
		    "e150c8939c00000000000000000000000000000000000000000000016e2d5ccb9e4905ecd6ec58a1a594ee1750c8c15459d13540175c48ed41f015e1",
		    // basepoint G
		    "04 d1e1c7b9 cfe38c13 bf6558b8 01cc985a f0fa1360 ddf7246b 75232425 9ad9cf45 a31426aa b1b04273 c03136a5 a6209663 fa830cf6 ceac0a42 c65d2489 6f0d797d 89af442d ea20a292 911989cb fbe79381 eb1e2e20 f7843901 59836b78 b07663fa 8232ac56 18d4820d 63954e4f c4cf421a bfc855af 42f1d815",
		    // order of basepoint G (480 Bit)
		    "e150c8939c00000000000000000000000000000000000000000000016e2d92f18c89782120d1be7ff777aed0e1a50263f8e8d74ce3c81e32acf1b33d",
		    // cofactor k
		    "01");
	}
    }

    public static final class PrimeCurve36 extends CurveParamsGFP {

	/**
	 * The OID of primeCurve36.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.2.9.0.36";

	public PrimeCurve36() {
	    super(
		    OID,
		    // curve coefficient a
		    "9b74038492f70b24b3395b0c082fb53c51b16c620ee048ad73c849b97445bb79db8aaff8ad99c213af994f0cf80518c71ede31e9ce7e674c23b8e74110",
		    // curve coefficient b
		    "67a2ad030ca4b218777b92080575237d8bcb9d96b49585c8f7dadbd0f82e7cfbe7b1caa5c9112c0d1fbb8a08a558bb2f69e9769bdefeef8817d09a2b60",
		    // prime p
		    "287f98f87f4000000000000000000000000000000000000000000000014f8f4891818707a2537fdd5882149d6cd7ff1589be96ad985028e51ccf5dcf179",
		    // basepoint G
		    "04 0109 0a75fef2 70032de3 20c4911f c5f886e4 de4ee75b e83fe973 a227f9aa a57fe2d0 92d5ade6 4efc67b4 1fc068cf 1893bb68 bc958b58 777ab1ba 0901f9ad 00b2 36223907 263b5a1c c4dc692c 8b88f64d 13b85f31 87e04414 a13ba94f f81ca11f 8fbe89fc 0543d976 e09aa000 15f02395 9dfd584a 0b2995c9 da84ee83",
		    // order of basepoint G (490 Bit)
		    "287f98f87f4000000000000000000000000000000000000000000000014f918573aa335f53c65ece4c4c28dfcd658d15c0280cf98d158053b0dcce6c62b",
		    // cofactor k
		    "01");
	}
    }

    public static final class PrimeCurve37 extends CurveParamsGFP {

	/**
	 * The OID of primeCurve37.
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.2.9.0.37";

	public PrimeCurve37() {
	    super(
		    OID,
		    // curve coefficient a
		    "10a47eb2095c6b6b978f03fbb62073efde13e018ab81ebcff802f3ea01a27df2044722dc1ffc06ca23fddd956280ccf8cc931d8c5e17bbdc3247f39336f11",
		    // curve coefficient b
		    "826ec1f35a1f3f683e12908e3fbf411947b83b29d31834ee6a0ce81e8725a74f4e485711fee423f344b860009b5ff7a052af6363fe1a468bf494ed256f37",
		    // prime p
		    "9750c68a6580000000000000000000000000000000000000000000000027a1a30056b7d324cdaf737f5a071ba5445a730825c0f4cacc7dc500a0310cf6383",
		    // basepoint G
		    "04 00013e94 cd5af6fd 110400c3 1a26528a 5baa3a88 c9e49b78 13a6f112 0ebcab0a fcc1f76f 0e8140cc 9122247c cc41015b 7cbeb6c0 5d8b8cfa eac5fd6b d0b3c57d 0004f717 834c14d9 faec80f9 93a2b521 2da69694 aabb7189 7bdd3507 def108fa fdb1e9d5 61a1e7c8 26e4cde8 990c71f7 b0def03a 577d0cc0 be971f75 d004f68a",
		    // order of basepoint G (500 Bit)
		    "9750c68a6580000000000000000000000000000000000000000000000027a1f3343f92ab62a57ed41d372216b5f8055a19d7ae06e4caed64532084ceebe45",
		    // cofactor k
		    "01");
	}
    }

    public static final class PrimeCurve38 extends CurveParamsGFP {

	/**
	 * The OID of primeCurve38 (this is also the NIST curve P-521).
	 */
	public static final String OID = "1.3.6.1.4.1.8301.3.1.2.9.0.38";

	public PrimeCurve38() {
	    super(
		    OID,
		    // curve coefficient a
		    "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffFC",
		    // curve coefficient b
		    "051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
		    // prime p
		    "1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		    // basepoint G
		    "0400C6 858E06B7 0404E9CD 9E3ECB66 2395B442 9C648139 053FB521 F828AF60 6B4D3DBA A14B5E77 EFE75928 FE1DC127 A2ffA8DE 3348B3C1 856A429B F97E7E31 C2E5BD66 0118 39296A78 9A3BC004 5C8A5FB4 2C7D1BD9 98F54449 579B4468 17AFBD17 273E662C 97EE7299 5EF42640 C550B901 3FAD0761 353C7086 A272C240 88BE9476 9FD16650",
		    // order of basepoint G (521 Bit)
		    "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
		    // cofactor k
		    "01");
	}
    }

    /*-------------------------------------------------
     * CHARACTERISTIC 2 CURVES
     -------------------------------------------------*/

    public static final class C2pnb163v1 extends CurveParamsGF2nPentanomial {

	/**
	 * The OID of c2pnb163v1.
	 */
	public static final String OID = "1.2.840.10045.3.0.1";

	public C2pnb163v1() {
	    super(OID,
	    // curve coefficient a
		    "07 2546B543 5234A422 E0789675 F432C894 35DE5242",
		    // curve coefficient b
		    "00 C9517D06 D5240D3C FF38C74B 20B6CD4D 6F9DD4D9",
		    // basepoint G
		    "0307 AF699895 46103D79 329FCC3D 74880F33 BBE803CB",
		    // order of basepoint G
		    "04 00000000 00000000 0001E60F C8821CC7 4DAEAFC1",
		    // extension degree n
		    "163",
		    // cofactor h
		    "02",
		    // pentanomial coefficients
		    "1", "2", "8");
	}
    }

    public static final class C2pnb163v2 extends CurveParamsGF2nPentanomial {

	/**
	 * The OID of c2pnb163v2.
	 */
	public static final String OID = "1.2.840.10045.3.0.2";

	public C2pnb163v2() {
	    super(OID,
	    // curve coefficient a
		    "01 08B39E77 C4B108BE D981ED0E 890E117C 511CF072",
		    // curve coefficient b
		    "06 67ACEB38 AF4E488C 407433FF AE4F1C81 1638DF20",
		    // basepoint G
		    "0300 24266E4E B5106D0A 964D92C4 860E2671 DB9B6CC5",
		    // order of basepoint G
		    "03 FFFFFFFF FFFFFFFF FFFDF64D E1151ADB B78F10A7",
		    // extension degree n
		    "163",
		    // cofactor h
		    "02",
		    // pentanomial coefficients
		    "1", "2", "8");
	}
    }

    public static final class C2pnb163v3 extends CurveParamsGF2nPentanomial {

	/**
	 * The OID of c2pnb163v3.
	 */
	public static final String OID = "1.2.840.10045.3.0.3";

	public C2pnb163v3() {
	    super(OID,
	    // curve coefficient a
		    "07 A526C63D 3E25A256 A007699F 5447E32A E456B50E",
		    // curve coefficient b
		    "03 F7061798 EB99E238 FD6F1BF9 5B48FEEB 4854252B",
		    // basepoint G
		    "0202 F9F87B7C 574D0BDE CF8A22E6 524775F9 8CDEBDCB",
		    // order of basepoint G
		    "03 FFFFFFFF FFFFFFFF FFFE1AEE 140F110A FF961309",
		    // extension degree n
		    "163",
		    // cofactor h
		    "02",
		    // pentanomial coefficients
		    "1", "2", "8");
	}
    }

    public static final class C2tnb191v1 extends CurveParamsGF2nTrinomial {

	/**
	 * The OID of c2tnb191v1.
	 */
	public static final String OID = "1.2.840.10045.3.0.5";

	public C2tnb191v1() {
	    super(OID,
	    // curve coefficient a
		    "2866537B 67675263 6A68F565 54E12640 276B649E F7526267",
		    // curve coefficient b
		    "2E45EF57 1F00786F 67B0081B 9495A3D9 5462F5DE 0AA185EC",
		    // basepoint G
		    "02 36B3DAF8 A23206F9 C4F299D7 B21A9C36 9137F2C8 4AE1AA0D",
		    // order of basepoint G
		    "40000000 00000000 00000000 04A20E90 C39067C8 93BBB9A5",
		    // extension degree n
		    "191",
		    // cofactor h
		    "02",
		    // trinomial coefficient
		    "9");
	}
    }

    public static final class C2tnb191v2 extends CurveParamsGF2nTrinomial {

	/**
	 * The OID of c2tnb191v2.
	 */
	public static final String OID = "1.2.840.10045.3.0.6";

	public C2tnb191v2() {
	    super(OID,
	    // curve coefficient a
		    "40102877 4D7777C7 B7666D13 66EA4320 71274F89 FF01E718",
		    // curve coefficient b
		    "0620048D 28BCBD03 B6249C99 182B7C8C D19700C3 62C46A01",
		    // basepoint G
		    "02 3809B2B7 CC1B28CC 5A87926A AD83FD28 789E81E2 C9E3BF10",
		    // order of basepoint G
		    "20000000 00000000 00000000 50508CB8 9F652824 E06B8173",
		    // extension degree n
		    "191",
		    // cofactor h
		    "04",
		    // trinomial coefficient
		    "9");
	}
    }

    public static final class C2tnb191v3 extends CurveParamsGF2nTrinomial {

	/**
	 * The OID of c2tnb191v3.
	 */
	public static final String OID = "1.2.840.10045.3.0.7";

	public C2tnb191v3() {
	    super(OID,
	    // curve coefficient a
		    "6C010747 56099122 22105691 1C77D77E 77A777E7 E7E77FCB",
		    // curve coefficient b
		    "71FE1AF9 26CF8479 89EFEF8D B459F663 94D90F32 AD3F15E8",
		    // basepoint G
		    "03 375D4CE2 4FDE4344 89DE8746 E7178601 5009E66E 38A926DD",
		    // order of basepoint G
		    "15555555 55555555 55555555 610C0B19 6812BFB6 288A3EA3",
		    // extension degree n
		    "191",
		    // cofactor h
		    "06",
		    // trinomial coefficient
		    "9");
	}
    }

    public static final class C2pnb208w1 extends CurveParamsGF2nPentanomial {

	/**
	 * The OID of c2pnb208w1.
	 */
	public static final String OID = "1.2.840.10045.3.0.10";

	public C2pnb208w1() {
	    super(
		    OID,
		    // curve coefficient a
		    "0000 00000000 00000000 00000000 00000000 00000000 00000000",
		    // curve coefficient b
		    "C861 9ED45A62 E6212E11 60349E2B FA844439 FAFC2A3F D1638F9E",
		    // basepoint G
		    "0289FD FBE4ABE1 93DF9559 ECF07AC0 CE78554E 2784EB8C 1ED1A57A",
		    // order of basepoint G
		    " 01 01BAF95C 9723C57B 6C21DA2E FF2D5ED5 88BDD571 7E212F9D",
		    // extension degree n
		    "208",
		    // cofactor h
		    "FE48",
		    // pentanomial coefficients
		    "1", "2", "83");
	}
    }

    public static final class C2tnb239v1 extends CurveParamsGF2nTrinomial {

	/**
	 * The OID of c2tnb239v1.
	 */
	public static final String OID = "1.2.840.10045.3.0.11";

	public C2tnb239v1() {
	    super(
		    OID,
		    // curve coefficient a
		    "3201 0857077C 5431123A 46B80890 6756F543 423E8D27 87757812 5778AC76",
		    // curve coefficient b
		    "7904 08F2EEDA F392B012 EDEFB339 2F30F432 7C0CA3F3 1FC383C4 22AA8C16",
		    // basepoint G
		    "025792 7098FA93 2E7C0A96 D3FD5B70 6EF7E5F5 C156E16B 7E7C8603 8552E91D",
		    // order of basepoint G
		    "2000 00000000 00000000 00000000 000F4D42 FFE1492A 4993F1CA D666E447",
		    // extension degree n
		    "239",
		    // cofactor h
		    "04",
		    // trinomial coefficient
		    "36");
	}
    }

    public static final class C2tnb239v2 extends CurveParamsGF2nTrinomial {

	/**
	 * The OID of c2tnb239v2.
	 */
	public static final String OID = "1.2.840.10045.3.0.12";

	public C2tnb239v2() {
	    super(
		    OID,
		    // curve coefficient a
		    "4230 017757A7 67FAE423 98569B74 6325D453 13AF0766 266479B7 5654E65F",
		    // curve coefficient b
		    "5037 EA654196 CFF0CD82 B2C14A2F CF2E3FF8 775285B5 45722F03 EACDB74B",
		    // basepoint G
		    "0228F9 D04E9000 69C8DC47 A08534FE 76D2B900 B7D7EF31 F5709F20 0C4CA205",
		    // order of basepoint G
		    "1555 55555555 55555555 55555555 553C6F28 85259C31 E3FCDF15 4624522D",
		    // extension degree n
		    "239",
		    // cofactor h
		    "06",
		    // trinomial coefficient
		    "36");
	}
    }

    public static final class C2tnb239v3 extends CurveParamsGF2nTrinomial {

	/**
	 * The OID of c2tnb239v3.
	 */
	public static final String OID = "1.2.840.10045.3.0.13";

	public C2tnb239v3() {
	    super(
		    OID,
		    // curve coefficient a
		    "0123 8774666A 67766D66 76F778E6 76B66999 176666E6 87666D87 66C66A9F",
		    // curve coefficient b
		    "6A94 1977BA9F 6A435199 ACFC5106 7ED587F5 19C5ECB5 41B8E441 11DE1D40",
		    // basepoint G
		    "0370F6 E9D04D28 9C4E8991 3CE3530B FDE90397 7D42B146 D539BF1B DE4E9C92",
		    // order of basepoint G
		    "0CCC CCCCCCCC CCCCCCCC CCCCCCCC CCAC4912 D2D9DF90 3EF9888B 8A0E4CFF",
		    // extension degree n
		    "239",
		    // cofactor h
		    "0A",
		    // trinomial coefficient
		    "36");
	}
    }

    public static final class C2pnb272w1 extends CurveParamsGF2nPentanomial {

	/**
	 * The OID of c2pnb272w1.
	 */
	public static final String OID = "1.2.840.10045.3.0.16";

	public C2pnb272w1() {
	    super(
		    OID,
		    // curve coefficient a
		    "91A0 91F03B5F BA4AB2CC F49C4EDD 220FB028 712D42BE 752B2C40 094DBACD B586FB20",
		    // curve coefficient b
		    "7167 EFC92BB2 E3CE7C8A AAFF34E1 2A9C5570 03D7C73A 6FAF003F 99F6CC84 82E540F7",
		    // basepoint G
		    " 026108 BABB2CEE BCF78705 8A056CBE 0CFE622D 7723A289 E08A07AE 13EF0D10 D171DD8D",
		    // order of basepoint G
		    "01 00FAF513 54E0E39E 4892DF6E 319C72C8 161603FA 45AA7B99 8A167B8F 1E629521",
		    // extension degree n
		    "272",
		    // cofactor h
		    "FF06",
		    // pentanomial coefficients
		    "1", "3", "56");
	}
    }

    public static final class C2tnb359v1 extends CurveParamsGF2nTrinomial {

	/**
	 * The OID of c2tnb359v1.
	 */
	public static final String OID = "1.2.840.10045.3.0.18";

	public C2tnb359v1() {
	    super(
		    OID,
		    // curve coefficient a
		    "56 67676A65 4B20754F 356EA920 17D94656 7C466755 56F19556 A04616B5 67D223A5 E05656FB 549016A9 6656A557",
		    // curve coefficient b
		    "24 72E2D019 7C49363F 1FE7F5B6 DB075D52 B6947D13 5D8CA445 805D39BC 34562608 9687742B 6329E706 80231988",
		    // basepoint G
		    "033C 258EF304 7767E7ED E0F1FDAA 79DAEE38 41366A13 2E163ACE D4ED2401 DF9C6BDC DE98E8E7 07C07A22 39B1B097",
		    // order of basepoint G
		    "01 AF286BCA 1AF286BC A1AF286B CA1AF286 BCA1AF28 6BC9FB8F 6B85C556 892C20A7 EB964FE7 719E74F4 90758D3B",
		    // extension degree n
		    "359",
		    // cofactor h
		    "4C",
		    // trinomial coefficient
		    "68");
	}
    }

    public static final class C2pnb368w1 extends CurveParamsGF2nPentanomial {

	/**
	 * The OID of c2pnb368w1.
	 */
	public static final String OID = "1.2.840.10045.3.0.19";

	public C2pnb368w1() {
	    super(
		    OID,
		    // curve coefficient a
		    "E0D2 EE250952 06F5E2A4 F9ED229F 1F256E79 A0E2B455 970D8D0D 865BD947 78C576D6 2F0AB751 9CCD2A1A 906AE30D",
		    // curve coefficient b
		    "FC12 17D4320A 90452C76 0A58EDCD 30C8DD06 9B3C3445 3837A34E D50CB549 17E1C211 2D84D164 F444F8F7 4786046A",
		    // basepoint G
		    "021085 E2755381 DCCCE3C1 557AFA10 C2F0C0C2 825646C5 B34A394C BCFA8BC1 6B22E7E7 89E927BE 216F02E1 FB136A5F",
		    // order of basepoint G
		    "01 0090512D A9AF72B0 8349D98A 5DD4C7B0 532ECA51 CE03E2D1 0F3B7AC5 79BD87E9 09AE40A6 F131E9CF CE5BD967",
		    // extension degree n
		    "368",
		    // cofactor h
		    "FF70",
		    // pentanomial coefficients
		    "1", "2", "85");
	}
    }

    public static final class C2tnb431r1 extends CurveParamsGF2nTrinomial {

	/**
	 * The OID of c2tnb431r1.
	 */
	public static final String OID = "1.2.840.10045.3.0.20";

	public C2tnb431r1() {
	    super(
		    OID,
		    // curve coefficient a
		    "1A82 7EF00DD6 FC0E234C AF046C6A 5D8A8539 5B236CC4 AD2CF32A 0CADBDC9 DDF620B0 EB9906D0 957F6C6F EACD6154 68DF104D E296CD8F",
		    // curve coefficient b
		    "10D9 B4A3D904 7D8B1543 59ABFB1B 7F5485B0 4CEB8682 37DDC9DE DA982A67 9A5A919B 626D4E50 A8DD731B 107A9962 381FB5D8 07BF2618",
		    // basepoint G
		    "02120F C05D3C67 A99DE161 D2F40926 22FECA70 1BE4F50F 4758714E 8A87BBF2 A658EF8C 21E7C5EF E965361F 6C2999C0 C247B0DB D70CE6B7",
		    // order of basepoint G
		    "03 40340340 34034034 03403403 40340340 34034034 03403403 40340323 C313FAB5 0589703B 5EC68D35 87FEC60D 161CC149 C1AD4A91",
		    // extension degree n
		    "431",
		    // cofactor h
		    "2760",
		    // trinomial coefficient
		    "120");
	}
    }

    /**
     * Array holding the key sizes to index the <tt>defaultParamsMap</tt>
     * hashtable.
     */
    private static final int[] keySizes = { 112, 128, 160, 170, 180, 190, 192,
	    200, 210, 220, 224, 230, 239, 240, 250, 256, 260, 270, 280, 290,
	    300, 310, 320, 330, 340, 350, 360, 370, 380, 384, 390, 400, 410,
	    420, 430, 440, 450, 460, 470, 480, 490, 500, 512 };

    /**
     * Map holding default curves parameters (specified by their OID)
     */
    private static Hashtable defaultParamsMap;

    /**
     * Construct the "keySize -> default curve parameters" mapping via static
     * initialization.
     */
    static {
	defaultParamsMap = new Hashtable();
	defaultParamsMap.put(new Integer(112), "secp112r1");
	defaultParamsMap.put(new Integer(128), "secp128r1");
	defaultParamsMap.put(new Integer(160), "brainpoolP160r1");
	defaultParamsMap.put(new Integer(170), "primeCurve2");
	defaultParamsMap.put(new Integer(180), "primeCurve3");
	defaultParamsMap.put(new Integer(190), "primeCurve4");
	defaultParamsMap.put(new Integer(192), "brainpoolP192r1");
	defaultParamsMap.put(new Integer(200), "primeCurve5");
	defaultParamsMap.put(new Integer(210), "primeCurve6");
	defaultParamsMap.put(new Integer(220), "primeCurve7");
	defaultParamsMap.put(new Integer(224), "brainpoolP224r1");
	defaultParamsMap.put(new Integer(230), "primeCurve9");
	defaultParamsMap.put(new Integer(239), "prime239v1");
	defaultParamsMap.put(new Integer(240), "primeCurve10");
	defaultParamsMap.put(new Integer(250), "primeCurve11");
	defaultParamsMap.put(new Integer(256), "brainpoolP256r1");
	defaultParamsMap.put(new Integer(260), "primeCurve12");
	defaultParamsMap.put(new Integer(270), "primeCurve13");
	defaultParamsMap.put(new Integer(280), "primeCurve14");
	defaultParamsMap.put(new Integer(290), "primeCurve15");
	defaultParamsMap.put(new Integer(300), "primeCurve16");
	defaultParamsMap.put(new Integer(310), "primeCurve17");
	defaultParamsMap.put(new Integer(320), "brainpoolP320r1");
	defaultParamsMap.put(new Integer(330), "primeCurve19");
	defaultParamsMap.put(new Integer(340), "primeCurve20");
	defaultParamsMap.put(new Integer(350), "primeCurve21");
	defaultParamsMap.put(new Integer(360), "primeCurve22");
	defaultParamsMap.put(new Integer(370), "primeCurve23");
	defaultParamsMap.put(new Integer(380), "primeCurve24");
	defaultParamsMap.put(new Integer(384), "brainpoolP384r1");
	defaultParamsMap.put(new Integer(390), "primeCurve26");
	defaultParamsMap.put(new Integer(400), "primeCurve27");
	defaultParamsMap.put(new Integer(410), "primeCurve28");
	defaultParamsMap.put(new Integer(420), "primeCurve29");
	defaultParamsMap.put(new Integer(430), "primeCurve30");
	defaultParamsMap.put(new Integer(440), "primeCurve31");
	defaultParamsMap.put(new Integer(450), "primeCurve32");
	defaultParamsMap.put(new Integer(460), "primeCurve33");
	defaultParamsMap.put(new Integer(470), "primeCurve34");
	defaultParamsMap.put(new Integer(480), "primeCurve35");
	defaultParamsMap.put(new Integer(490), "primeCurve36");
	defaultParamsMap.put(new Integer(500), "primeCurve37");
	defaultParamsMap.put(new Integer(512), "brainpoolP512r1");
    }

    /**
     * Default constructor (private)
     */
    private CurveRegistry() {
	// empty
    };

    /**
     * Return the OID of the default curve for the given key size.
     * 
     * @param keySize
     *                the key size
     * @return the OID of the default curve for the given key size
     * @throws InvalidAlgorithmParameterException
     *                 if no default parameters exist for the specified key
     *                 size.
     */
    public static String getDefaultCurveParams(int keySize)
	    throws InvalidAlgorithmParameterException {
	int index = 0;
	int size;
	do {
	    size = keySizes[index++];
	} while ((keySize > size) && (index < keySizes.length));
	if (keySize > size) {
	    throw new InvalidAlgorithmParameterException(
		    "No default parameters exist for key size '" + keySize
			    + "'.");
	}
	return (String) defaultParamsMap.get(new Integer(size));
    }

}
